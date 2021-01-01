/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.buildtools.toolusage;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.unboundid.ldap.sdk.unboundidds.Launcher;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.ExampleCommandLineArgument;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.SubCommand;



/**
 * This class provides an Ant task that can be used to obtain usage output from
 * all of the tools that we provide with the LDAP SDK.  The usage output will
 * be in both plain text and HTML forms.
 */
public final class GenerateToolUsage
       extends Task
{
  // The output directory in which the usage information will be written.
  private File outputDirectory;

  // A buffer to use for building HTML content.
  private final StringBuilder htmlBuffer = new StringBuilder();



  /**
   * Creates a new instance of this Ant task.
   */
  public GenerateToolUsage()
  {
    outputDirectory = null;
  }



  /**
   * Retrieves the output directory in which the usage information will be
   * written.
   *
   * @return  The output directory in which the usage information will be
   *          written.
   */
  public File getOutputDirectory()
  {
    return outputDirectory;
  }



  /**
   * Sets the output directory in which the usage information will be written.
   *
   * @param  outputDirectory  The output directory in which the usage
   *                          information will be written.
   */
  public void setOutputDirectory(final File outputDirectory)
  {
    this.outputDirectory = outputDirectory;
  }



  /**
   * Generates usage information for each of the tools provided with the LDAP
   * SDK.
   *
   * @throws  BuildException  If a problem occurs while generating the usage
   *                          information.
   */
  @Override()
  public void execute()
         throws BuildException
  {
    final List<Class<? extends CommandLineTool>> toolClasses =
         Launcher.getToolClasses();
    for (final Class<? extends CommandLineTool> c : toolClasses)
    {
      try
      {
        generateTextUsage(c);
        generateHTMLUsage(c);
      }
      catch (final Exception e)
      {
        throw new BuildException(
             "Error creating plain-text usage information for tool class " +
                  c.getName() + ":  " + StaticUtils.getExceptionMessage(e),
             e);
      }
    }

    generateHTMLIndexPage(toolClasses);
  }



  /**
   * Generates plain-text usage information for the specified command-line tool.
   *
   * @param  c  The command-line tool class for which to obtain usage
   *            information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void generateTextUsage(final Class<? extends CommandLineTool> c)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final CommandLineTool t = Launcher.getToolInstance(c, out, out);
    final ArgumentParser p = t.createArgumentParser();

    final File outputFile = new File(outputDirectory, t.getToolName() + ".txt");
    try (final PrintWriter w = new PrintWriter(outputFile))
    {
      if (p.hasSubCommands())
      {
        w.println("The " + t.getToolName() + " Command-Line Tool");
        w.println();

        w.println("Global Usage:");
        w.println();
        w.println(p.getUsageString(79));

        writeExamples(w, t.getToolName(), null, t.getExampleUsages());

        w.println();
        w.println();
        w.println();
        w.println("Available Subcommands:");
        final List<SubCommand> subCommands = p.getSubCommands();
        if (anySubcommandsHaveMultipleNames(subCommands))
        {
          for (final SubCommand sc : subCommands)
          {
            final List<String> names = sc.getNames(false);
            if (! names.isEmpty())
            {
              w.println();
              final Iterator<String> nameIterator = names.iterator();
              w.println("* " + nameIterator.next());
              while  (nameIterator.hasNext())
              {
                w.println("  " + nameIterator.next());
              }
            }
          }
        }
        else
        {
          for (final SubCommand sc : subCommands)
          {
            w.println("* " + sc.getPrimaryName());
          }
        }

        for (final SubCommand sc : p.getSubCommands())
        {
          w.println();
          w.println();
          w.println();
          w.println("Usage for subcommand " + sc.getPrimaryName() + ':');
          w.println();
          w.println(sc.getArgumentParser().getUsageString(79));

          writeExamples(w, t.getToolName(), sc.getPrimaryName(),
               sc.getExampleUsages());
        }
      }
      else
      {
        w.println("Usage for " + t.getToolName() + ":");
        w.println();
        w.println(p.getUsageString(79));

        writeExamples(w, t.getToolName(), null, t.getExampleUsages());
      }
    }
  }



  /**
   * Generates HTML-formatted usage information for the specified command-line
   * tool.
   *
   * @param  c  The command-line tool class for which to obtain usage
   *            information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void generateHTMLUsage(final Class<? extends CommandLineTool> c)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final CommandLineTool t = Launcher.getToolInstance(c, out, out);
    final ArgumentParser p = t.createArgumentParser();

    final File outputFile =
         new File(outputDirectory, t.getToolName() + ".html");
    try (final PrintWriter w = new PrintWriter(outputFile))
    {
      w.println("<!DOCTYPE HTML PUBLIC " +
           "\"-//W3C//DTD HTML 4.01 Transitional//EN\" " +
           "\"http://www.w3.org/TR/html4/loose.dtd\">");
      w.println("<html>");
      w.println("  <head>");
      w.println("    <title>The " + htmlEscape(t.getToolName()) +
           " Command-Line Tool</title>");
      w.println("    <meta http-equiv=\"Content-Type\" " +
           "content=\"text/html; charset=utf-8\">");
      w.println("    <link rel=\"stylesheet\" " +
           "href=\"../unboundid.css\" type=\"text/css\">");
      w.println("    <link rel=\"shortcut icon\" " +
           "href=\"../images/favicon.ico\">");
      w.println("  </head>");

      w.println();
      w.println("  <body>");
      w.println("    <h1>The " + htmlEscape(t.getToolName()) +
           " Command-Line Tool</h1>");
      w.println();

      if (p.hasSubCommands())
      {
        if (t.getToolDescription() != null)
        {
          w.println("    <p>");
          w.println("      " + htmlEscape(t.getToolDescription()));
          w.println("    </p>");

          if (t.getAdditionalDescriptionParagraphs() != null)
          {
            for (final String s : t.getAdditionalDescriptionParagraphs())
            {
              w.println("    <p>");
              w.println("      " + htmlEscape(s));
              w.println("    </p>");
            }
          }
        }

        printHTMLUsage(w, t, p);

        w.println("    <p>");
        w.println("      This tool uses subcommands to indicate which " +
             "function you want to perform.");
        w.println("      <br>");
        w.println("      <a href=\"#available-subcommands\">Jump to a list " +
             "of the available subcommands.</a>");
        w.println("    </p>");

        printHTMLArgs(w, p);
        printHTMLExamples(w, t.getToolName(), null, t.getExampleUsages());

        final StringBuilder buffer = new StringBuilder();
        w.println();
        w.println("    <p>&nbsp;</p>");
        w.println();
        w.println("    <h3><a name=\"available-subcommands\">Available " +
             "Subcommands</a></h3>");
        w.println("    <ul>");
        for (final SubCommand subCommand : p.getSubCommands())
        {
          buffer.setLength(0);
          for (final String name : subCommand.getNames(false))
          {
            if (buffer.length() > 0)
            {
              buffer.append(" / ");
              buffer.append(name);
            }
            else
            {
              buffer.append("<a href=\"#subcommand-");
              buffer.append(subCommand.getPrimaryName());
              buffer.append("\">");
              buffer.append(name);
              buffer.append("</a>");
            }
          }

          w.println("      <li>");
          w.println("        " + buffer + " &mdash; " +
               htmlEscape(subCommand.getDescription()));
          w.println("        <br><br>");
          w.println("      </li>");
        }
        w.println("    </ul>");

        for (final SubCommand sc : p.getSubCommands())
        {
          w.println();
          w.println("    <p>&nbsp;</p>");
          w.println();
          w.println("    <h2><a name=\"subcommand-" + sc.getPrimaryName() +
               "\">Usage For Subcommand " + sc.getPrimaryName() +
               "</a></h2>");
          w.println("    <p>" + htmlEscape(sc.getDescription()) + "</p>");
          printHTMLArgs(w, sc.getArgumentParser());
          printHTMLExamples(w, t.getToolName(), sc.getPrimaryName(),
               sc.getExampleUsages());
        }
      }
      else
      {
        if (t.getToolDescription() != null)
        {
          w.println("    <p>");
          w.println("      " + htmlEscape(t.getToolDescription()));
          w.println("    </p>");

          if (t.getAdditionalDescriptionParagraphs() != null)
          {
            for (final String s : t.getAdditionalDescriptionParagraphs())
            {
              w.println("    <p>");
              w.println("      " + htmlEscape(s));
              w.println("    </p>");
            }
          }
        }

        printHTMLUsage(w, t, p);

        printHTMLArgs(w, p);
        printHTMLExamples(w, t.getToolName(), null, t.getExampleUsages());
      }


      w.println("  </body>");
      w.println("</html>");
    }
  }



  /**
   * Indicates whether any of the subcommands in the provided list have multiple
   * public names.
   *
   * @param  l  The list of subcommands for which to make the determination.
   *
   * @return  {@code true} if any of the subcommands has multiple public names,
   *          or {@code false} if not.
   */
  private static boolean anySubcommandsHaveMultipleNames(
                              final List<SubCommand> l)
  {
    for (final SubCommand sc : l)
    {
      if (sc.getNames(false).size() > 1)
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Writes the example usages for the provided tool or subcommand to the
   * given writer.
   *
   * @param  w  The writer to use to write the example usages.  It must not be
   *            {@code null}.
   * @param  t  The name of the tool.  It must not be {@code null}.
   * @param  s  The name of the subcommand.  It may be {@code null} if the
   *            examples are not for a specific subcommand.
   * @param  m  The map of example usages.
   */
  private static void writeExamples(final PrintWriter w, final String t,
                                    final String s,
                                    final LinkedHashMap<String[],String> m)
  {
    if ((m == null) || m.isEmpty())
    {
      return;
    }

    w.println("Examples");
    for (final Map.Entry<String[],String> e : m.entrySet())
    {
      final String[] args = e.getKey();
      final String description = e.getValue();

      w.println();
      for (final String line : StaticUtils.wrapLine(description, 77))
      {
        w.println("  " + line);
      }

      w.println();

      final StringBuilder buffer = new StringBuilder();
      buffer.append("    ");
      buffer.append(t);

      if (s != null)
      {
        buffer.append(' ');
        buffer.append(s);
      }

      for (int i=0; i < args.length; i++)
      {
        buffer.append(' ');

        // If the argument has a value, then make sure to keep it on the same
        // line as the argument name.  This may introduce false positives due to
        // unnamed trailing arguments, but the worst that will happen that case
        // is that the output may be wrapped earlier than necessary one time.
        String arg = args[i];
        if (arg.startsWith("-"))
        {
          if ((i < (args.length - 1)) && (! args[i+1].startsWith("-")))
          {
            final ExampleCommandLineArgument cleanArg =
                ExampleCommandLineArgument.getCleanArgument(args[i+1]);
            arg += ' ' + cleanArg.getLocalForm();
            i++;
          }
        }
        else
        {
          final ExampleCommandLineArgument cleanArg =
              ExampleCommandLineArgument.getCleanArgument(arg);
          arg = cleanArg.getLocalForm();
        }

        if ((buffer.length() + arg.length() + 2) < 79)
        {
          buffer.append(arg);
        }
        else
        {
          buffer.append('\\');
          w.println(buffer.toString());
          buffer.setLength(0);
          buffer.append("         ");
          buffer.append(arg);
        }
      }

      w.println(buffer.toString());
    }
  }



  /**
   * Performs any necessary escaping for the provided string.
   *
   * @param  s  The string to be escaped.
   *
   * @return  An HTML-escaped version of the provided string.
   */
  private String htmlEscape(final String s)
  {
    htmlBuffer.setLength(0);
    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '<':
          htmlBuffer.append("&lt;");
          break;
        case '>':
          htmlBuffer.append("&gt;");
          break;
        case '&':
          htmlBuffer.append("&amp;");
          break;
        default:
          htmlBuffer.append(c);
          break;
      }
    }

    return htmlBuffer.toString();
  }



  /**
   * Writes HTML-formatted usage information for the provided command-line tool
   * to the given writer.
   *
   * @param  w  The print writer to which the usage should be written.
   * @param  t  The command-line tool for which to obtain the usage.
   * @param  p  The tool's argument parser.
   */
  private void printHTMLUsage(final PrintWriter w, final CommandLineTool t,
                              final ArgumentParser p)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append(t.getToolName());

    if (p.hasSubCommands())
    {
      buffer.append(" <i>{subCommand}</i>");
    }

    buffer.append(" <i>{arguments}</i>");

    if (t.getTrailingArgumentsPlaceholder() != null)
    {
      buffer.append(" <i>");
      buffer.append(htmlEscape(t.getTrailingArgumentsPlaceholder()));
      buffer.append("</i>");
    }

    w.println("    <h3>Usage</h3>");
    w.println("    <blockquote><pre>" + buffer + "</pre></blockquote>");
  }



  /**
   * Writes HTML-formatted information about the arguments for the provided
   * argument parser to the given writer.
   *
   * @param  w  The writer to which the argument information should be
   *            printed.
   * @param  p  The argument parser whose arguments should be displayed.
   */
  private void printHTMLArgs(final PrintWriter w, final ArgumentParser p)
  {
    final LinkedHashMap<String,List<Argument>> argsByCategory =
         new LinkedHashMap<>(20);
    for (final Argument a : p.getNamedArguments())
    {
      List<Argument> argList;
      if (a.getArgumentGroupName() == null)
      {
        argList = argsByCategory.get("");
        if (argList == null)
        {
          argList = new ArrayList<>(10);
          argsByCategory.put("", argList);
        }
      }
      else
      {
        argList = argsByCategory.get(a.getArgumentGroupName());
        if (argList == null)
        {
          argList = new ArrayList<>(10);
          argsByCategory.put(a.getArgumentGroupName(), argList);
        }
      }

      argList.add(a);
    }

    final List<Argument> ungroupedArgs = argsByCategory.remove("");
    if (ungroupedArgs != null)
    {
      if (argsByCategory.isEmpty())
      {
        if (p.hasSubCommands())
        {
          argsByCategory.put("Global Arguments", ungroupedArgs);
        }
        else
        {
          argsByCategory.put("Arguments", ungroupedArgs);
        }
      }
      else
      {
        argsByCategory.put("Additional Arguments", ungroupedArgs);
      }
    }

    final StringBuilder buffer = new StringBuilder();
    for (final Map.Entry<String,List<Argument>> e : argsByCategory.entrySet())
    {
      w.println("    <h3>" + htmlEscape(e.getKey()) + "</h3>");
      w.println("    <ul>");

      for (final Argument a : e.getValue())
      {
        w.println("      <li>");

        buffer.setLength(0);
        for (final Character c : a.getShortIdentifiers(false))
        {
          if (buffer.length() > 0)
          {
            buffer.append(" / ");
          }

          buffer.append("<tt>-");
          buffer.append(c);
          if (a.takesValue() && (a.getValuePlaceholder() != null))
          {
            buffer.append(" <i>");
            buffer.append(htmlEscape(a.getValuePlaceholder()));
            buffer.append("</i>");
          }
          buffer.append("</tt>");
        }

        for (final String s : a.getLongIdentifiers(false))
        {
          if (buffer.length() > 0)
          {
            buffer.append(" / ");
          }

          buffer.append("<tt>--");
          buffer.append(s);
          if (a.takesValue() && (a.getValuePlaceholder() != null))
          {
            buffer.append(" <i>");
            buffer.append(htmlEscape(a.getValuePlaceholder()));
            buffer.append("</i>");
          }
          buffer.append("</tt>");
        }

        buffer.append(" &mdash; ");
        buffer.append(htmlEscape(a.getDescription()));
        w.println("        " + buffer);

        if (a.getValueConstraints() != null)
        {
          w.println("        <br>");
          w.println("        " + htmlEscape(a.getValueConstraints()));
        }

        w.println("        <br><br>");
        w.println("      </li>");
      }

      w.println("    </ul>");
    }

    final List<Set<Argument>> requiredargumentSets =
         p.getRequiredArgumentSets();
    if (! requiredargumentSets.isEmpty())
    {
      w.println("    <h3>Required Argument Sets</h3>");
      w.println("    <ul>");

      for (final Set<Argument> requiredArgumentSet : requiredargumentSets)
      {
        buffer.setLength(0);
        for (final Argument a : requiredArgumentSet)
        {
          if (buffer.length() > 0)
          {
            buffer.append(", ");
          }

          buffer.append("<tt>");
          buffer.append(a.getIdentifierString());
          buffer.append("</tt>");
        }

        w.println("      <li>");
        w.println("        At least one of the following arguments must " +
             "be provided:  " + buffer);
        w.println("      </li>");
      }

      w.println("    </ul>");
    }


    final List<ObjectPair<Argument,Set<Argument>>> dependentArgumentSets =
         p.getDependentArgumentSets();
    if (! dependentArgumentSets.isEmpty())
    {
      w.println("    <h3>Dependent Argument Sets</h3>");
      w.println("    <ul>");

      for (final ObjectPair<Argument,Set<Argument>> dependentArgumentSet :
           dependentArgumentSets)
      {
        w.println("      <li>");
        final Set<Argument> argSet = dependentArgumentSet.getSecond();
        if (argSet.size() == 1)
        {
          w.println("        If the <tt>" +
               dependentArgumentSet.getFirst().getIdentifierString() +
               "</tt> argument is provided, then the <tt>" +
               argSet.iterator().next().getIdentifierString() +
               "</tt> argument must also be provided.");
        }
        else
        {
          buffer.setLength(0);
          for (final Argument a : argSet)
          {
            if (buffer.length() > 0)
            {
              buffer.append(", ");
            }

            buffer.append("<tt>");
            buffer.append(a.getIdentifierString());
            buffer.append("</tt>");
          }

          w.println("        If the <tt>" +
               dependentArgumentSet.getFirst().getIdentifierString() +
               "</tt> argument is provided, then at least one of the " +
               "following arguments must also be provided:  " + buffer);
        }

        w.println("      </li>");
      }

      w.println("    </ul>");
    }


    final List<Set<Argument>> exclusiveArgumentSets =
         p.getExclusiveArgumentSets();
    if (! exclusiveArgumentSets.isEmpty())
    {
      w.println("    <h3>Exclusive Argument Sets</h3>");
      w.println("    <ul>");

      for (final Set<Argument> exclusiveArgumentSet : exclusiveArgumentSets)
      {
        buffer.setLength(0);
        for (final Argument a : exclusiveArgumentSet)
        {
          if (buffer.length() > 0)
          {
            buffer.append(", ");
          }

          buffer.append("<tt>");
          buffer.append(a.getIdentifierString());
          buffer.append("</tt>");
        }

        w.println("      <li>");
        w.println("        The following arguments cannot be used " +
             "together:  " + buffer);
        w.println("      </li>");
      }

      w.println("    </ul>");
    }
  }



  /**
   * Writes HTML-formatted example usages for the provided tool or subcommand
   * to the given writer.
   *
   * @param  w  The writer to use to write the example usages.  It must not be
   *            {@code null}.
   * @param  t  The name of the tool.  It must not be {@code null}.
   * @param  s  The name of the subcommand.  It may be {@code null} if the
   *            examples are not for a specific subcommand.
   * @param  m  The map of example usages.
   */
  private void printHTMLExamples(final PrintWriter w, final String t,
                                 final String s,
                                 final LinkedHashMap<String[],String> m)
  {
    if ((m == null) || m.isEmpty())
    {
      return;
    }

    w.println("    <h3>Examples</h3>");
    for (final Map.Entry<String[],String> e : m.entrySet())
    {
      w.println("    <ul>");
      w.println("      <li>" + htmlEscape(e.getValue()) + "</li>");
      w.println("    </ul>");

      w.print("    <blockquote><pre>");

      final StringBuilder buffer = new StringBuilder();
      buffer.append("    ");
      buffer.append(t);

      if (s != null)
      {
        buffer.append(' ');
        buffer.append(s);
      }

      final String[] args = e.getKey();
      for (int i=0; i < args.length; i++)
      {
        buffer.append(' ');

        // If the argument has a value, then make sure to keep it on the same
        // line as the argument name.  This may introduce false positives due to
        // unnamed trailing arguments, but the worst that will happen that case
        // is that the output may be wrapped earlier than necessary one time.
        String arg = args[i];
        if (arg.startsWith("-"))
        {
          if ((i < (args.length - 1)) && (! args[i+1].startsWith("-")))
          {
            final ExampleCommandLineArgument cleanArg =
                ExampleCommandLineArgument.getCleanArgument(args[i+1]);
            arg += ' ' + cleanArg.getLocalForm();
            i++;
          }
        }
        else
        {
          final ExampleCommandLineArgument cleanArg =
              ExampleCommandLineArgument.getCleanArgument(arg);
          arg = cleanArg.getLocalForm();
        }

        if ((buffer.length() + arg.length() + 2) < 79)
        {
          buffer.append(arg);
        }
        else
        {
          buffer.append('\\');
          w.println(buffer.toString());
          buffer.setLength(0);
          buffer.append("         ");
          buffer.append(arg);
        }
      }

      w.println(buffer.toString() + "</pre></blockquote>");
    }
  }



  /**
   * Generates an HTML index page for the provided set of tools.
   *
   * @param  toolClasses  A list of classes that provide command-line tool
   *                      functionality.
   *
   * @throws  BuildException  If a problem is encountered while generating the
   *                          index page.
   */
  private void generateHTMLIndexPage(
                    final List<Class<? extends CommandLineTool>> toolClasses)
  {
    final File outputFile = new File(outputDirectory, "index.html");
    try (final PrintWriter w = new PrintWriter(outputFile))
    {
      w.println("<!DOCTYPE HTML PUBLIC " +
           "\"-//W3C//DTD HTML 4.01 Transitional//EN\" " +
           "\"http://www.w3.org/TR/html4/loose.dtd\">");
      w.println("<html>");
      w.println("  <head>");
      w.println("    <title>Available Commmand-Line Tools</title>");
      w.println("    <meta http-equiv=\"Content-Type\" " +
           "content=\"text/html; charset=utf-8\">");
      w.println("    <link rel=\"stylesheet\" " +
           "href=\"../unboundid.css\" type=\"text/css\">");
      w.println("    <link rel=\"shortcut icon\" " +
           "href=\"../images/favicon.ico\">");
      w.println("  </head>");

      w.println();
      w.println("  <body>");
      w.println("    <h1>Available Command-Line Tools</h1>");
      w.println("    <p>The following command-line tools are provided with " +
                "the UnboundID LDAP SDK for Java.  Click on each tool name " +
           "for usage information for that tool.</p>");

      final TreeMap<String,CommandLineTool> toolMap = new TreeMap<>();
      for (final Class<? extends CommandLineTool> toolClass : toolClasses)
      {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final CommandLineTool t = Launcher.getToolInstance(toolClass, out, out);
        toolMap.put(t.getToolName(), t);
      }

      for (final CommandLineTool t : toolMap.values())
      {
        w.println();
        w.println("    <h3><a href=\"" + t.getToolName() + ".html\">" +
             t.getToolName() + "</a></h3>");
        w.println("    <p>" + htmlEscape(t.getToolDescription()) + "</p>");
      }

      w.println("  </body>");
      w.println("</html>");
    }
    catch (final Exception e)
    {
      throw new BuildException(
           "Error creating the HTML index page:  " +
                StaticUtils.getExceptionMessage(e),
           e);
    }
  }
}

