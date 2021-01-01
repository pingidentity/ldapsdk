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
package com.unboundid.ldap.sdk.examples;



import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.IntegerArgument;



/**
 * This class provides a command-line tool that can be used to display a
 * complex LDAP search filter in a multi-line form that makes it easier to
 * visualize its hierarchy.  It will also attempt to simply the filter if
 * possible (using the {@link Filter#simplifyFilter} method) to remove
 * unnecessary complexity.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class IndentLDAPFilter
       extends CommandLineTool
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The name of the argument used to specify the number of additional spaces
   * to indent each level of hierarchy.
   */
  @NotNull private static final String ARG_INDENT_SPACES = "indent-spaces";



  /**
   * The name of the argument used to indicate that the tool should not attempt
   * to simplify the provided filter.
   */
  @NotNull private static final String ARG_DO_NOT_SIMPLIFY = "do-not-simplify";



  // The argument parser for this tool.
  @Nullable private ArgumentParser parser;



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  out   The output stream to which standard out should be written.
   *               It may be {@code null} if standard output should be
   *               suppressed.
   * @param  err   The output stream to which standard error should be written.
   *               It may be {@code null} if standard error should be
   *               suppressed.
   * @param  args  The command line arguments provided to this program.
   *
   * @return  A result code that indicates whether processing was successful.
   *          Any result code other than {@link ResultCode#SUCCESS} should be
   *          considered an error.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final IndentLDAPFilter indentLDAPFilter = new IndentLDAPFilter(out, err);
    return indentLDAPFilter.runTool(args);
  }



  /**
   * Creates a new instance of this command-line tool with the provided output
   * and error streams.
   *
   * @param  out  The output stream to which standard out should be written.  It
   *              may be {@code null} if standard output should be
   *               suppressed.
   * @param  err  The output stream to which standard error should be written.
   *              It may be {@code null} if standard error should be suppressed.
   */
  public IndentLDAPFilter(@Nullable final OutputStream out,
                          @Nullable final OutputStream err)
  {
    super(out, err);

    parser = null;
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "indent-ldap-filter";
  }



  /**
   * Retrieves a human-readable description for this tool.  If the description
   * should include multiple paragraphs, then this method should return the text
   * for the first paragraph, and the
   * {@link #getAdditionalDescriptionParagraphs()} method should be used to
   * return the text for the subsequent paragraphs.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "Parses a provided LDAP filter string and displays it a " +
         "multi-line form that makes it easier to understand its hierarchy " +
         "and embedded components.  If possible, it may also be able to " +
         "simplify the provided filter in certain ways (for example, by " +
         "removing unnecessary levels of hierarchy, like an AND embedded in " +
         "an AND).";
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Retrieves the minimum number of unnamed trailing arguments that must be
   * provided for this tool.  If a tool requires the use of trailing arguments,
   * then it must override this method and the {@link #getMaxTrailingArguments}
   * arguments to return nonzero values, and it must also override the
   * {@link #getTrailingArgumentsPlaceholder} method to return a
   * non-{@code null} value.
   *
   * @return  The minimum number of unnamed trailing arguments that may be
   *          provided for this tool.  A value of zero indicates that the tool
   *          may be invoked without any trailing arguments.
   */
  @Override()
  public int getMinTrailingArguments()
  {
    return 1;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that may be
   * provided for this tool.  If a tool supports trailing arguments, then it
   * must override this method to return a nonzero value, and must also override
   * the {@link CommandLineTool#getTrailingArgumentsPlaceholder} method to
   * return a non-{@code null} value.
   *
   * @return  The maximum number of unnamed trailing arguments that may be
   *          provided for this tool.  A value of zero indicates that trailing
   *          arguments are not allowed.  A negative value indicates that there
   *          should be no limit on the number of trailing arguments.
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return 1;
  }



  /**
   * Retrieves a placeholder string that should be used for trailing arguments
   * in the usage information for this tool.
   *
   * @return  A placeholder string that should be used for trailing arguments in
   *          the usage information for this tool, or {@code null} if trailing
   *          arguments are not supported.
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return "{filter}";
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * Adds the command-line arguments supported for use with this tool to the
   * provided argument parser.  The tool may need to retain references to the
   * arguments (and/or the argument parser, if trailing arguments are allowed)
   * to it in order to obtain their values for use in later processing.
   *
   * @param  parser  The argument parser to which the arguments are to be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding any of the
   *                             tool-specific arguments to the provided
   *                             argument parser.
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;

    final IntegerArgument indentColumnsArg = new IntegerArgument(null,
         ARG_INDENT_SPACES, false, 1, "{numSpaces}",
         "Specifies the number of spaces that should be used to indent each " +
              "additional level of filter hierarchy.  A value of zero " +
              "indicates that the hierarchy should be displayed without any " +
              "additional indenting.  If this argument is not provided, a " +
              "default indent of two spaces will be used.",
         0, Integer.MAX_VALUE, 2);
    indentColumnsArg.addLongIdentifier("indentSpaces", true);
    indentColumnsArg.addLongIdentifier("indent-columns", true);
    indentColumnsArg.addLongIdentifier("indentColumns", true);
    indentColumnsArg.addLongIdentifier("indent", true);
    parser.addArgument(indentColumnsArg);

    final BooleanArgument doNotSimplifyArg = new BooleanArgument(null,
         ARG_DO_NOT_SIMPLIFY, 1,
         "Indicates that the tool should not make any attempt to simplify " +
              "the provided filter.  If this argument is not provided, then " +
              "the tool will try to simplify the provided filter (for " +
              "example, by removing unnecessary levels of hierarchy, like an " +
              "AND embedded in an AND).");
    doNotSimplifyArg.addLongIdentifier("doNotSimplify", true);
    doNotSimplifyArg.addLongIdentifier("do-not-simplify-filter", true);
    doNotSimplifyArg.addLongIdentifier("doNotSimplifyFilter", true);
    doNotSimplifyArg.addLongIdentifier("dont-simplify", true);
    doNotSimplifyArg.addLongIdentifier("dontSimplify", true);
    doNotSimplifyArg.addLongIdentifier("dont-simplify-filter", true);
    doNotSimplifyArg.addLongIdentifier("dontSimplifyFilter", true);
    parser.addArgument(doNotSimplifyArg);
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Make sure that we can parse the filter string.
    final Filter filter;
    try
    {
      filter = Filter.create(parser.getTrailingArguments().get(0));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN,
           "ERROR:  Unable to parse the provided filter string:  " +
           StaticUtils.getExceptionMessage(e));
      return e.getResultCode();
    }


    // Construct the base indent string.
    final int indentSpaces =
         parser.getIntegerArgument(ARG_INDENT_SPACES).getValue();
    final char[] indentChars = new char[indentSpaces];
    Arrays.fill(indentChars, ' ');
    final String indentString = new String(indentChars);


    // Display an indented representation of the provided filter.
    final List<String> indentedFilterLines = new ArrayList<>(10);
    indentLDAPFilter(filter, "", indentString, indentedFilterLines);
    for (final String line : indentedFilterLines)
    {
      out(line);
    }


    // See if we can simplify the provided filter.
    if (! parser.getBooleanArgument(ARG_DO_NOT_SIMPLIFY).isPresent())
    {
      out();
      final Filter simplifiedFilter = Filter.simplifyFilter(filter, false);
      if (simplifiedFilter.equals(filter))
      {
        wrapOut(0, WRAP_COLUMN, "The provided filter cannot be simplified.");
      }
      else
      {
        wrapOut(0, WRAP_COLUMN, "The provided filter can be simplified to:");
        out();
        out("     ", simplifiedFilter.toString());
        out();
        wrapOut(0, WRAP_COLUMN,
             "An indented representation of the simplified filter:");
        out();

        indentedFilterLines.clear();
        indentLDAPFilter(simplifiedFilter, "", indentString,
             indentedFilterLines);
        for (final String line : indentedFilterLines)
        {
          out(line);
        }
      }
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Generates an indented representation of the provided filter.
   *
   * @param  filter               The filter to be indented.  It must not be
   *                              {@code null}.
   * @param  currentIndentString  A string that represents the current indent
   *                              that should be added before each line of the
   *                              filter.  It may be empty, but must not be
   *                              {@code null}.
   * @param  indentSpaces         A string that represents the number of
   *                              additional spaces that each subsequent level
   *                              of the hierarchy should be indented.  It may
   *                              be empty, but must not be {@code null}.
   * @param  indentedFilterLines  A list to which the lines that comprise the
   *                              indented filter should be added.  It must not
   *                              be {@code null}, and must be updatable.
   */
  public static void indentLDAPFilter(@NotNull final Filter filter,
                          @NotNull final String currentIndentString,
                          @NotNull final String indentSpaces,
                          @NotNull final List<String> indentedFilterLines)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        final Filter[] andComponents = filter.getComponents();
        if (andComponents.length == 0)
        {
          indentedFilterLines.add(currentIndentString + "(&)");
        }
        else
        {
          indentedFilterLines.add(currentIndentString + "(&");

          final String andComponentIndent =
               currentIndentString + " &" + indentSpaces;
          for (final Filter andComponent : andComponents)
          {
            indentLDAPFilter(andComponent, andComponentIndent, indentSpaces,
                 indentedFilterLines);
          }
          indentedFilterLines.add(currentIndentString + " &)");
        }
        break;


      case Filter.FILTER_TYPE_OR:
        final Filter[] orComponents = filter.getComponents();
        if (orComponents.length == 0)
        {
          indentedFilterLines.add(currentIndentString + "(|)");
        }
        else
        {
          indentedFilterLines.add(currentIndentString + "(|");

          final String orComponentIndent =
               currentIndentString + " |" + indentSpaces;
          for (final Filter orComponent : orComponents)
          {
            indentLDAPFilter(orComponent, orComponentIndent, indentSpaces,
                 indentedFilterLines);
          }
          indentedFilterLines.add(currentIndentString + " |)");
        }
        break;


      case Filter.FILTER_TYPE_NOT:
        indentedFilterLines.add(currentIndentString + "(!");
        indentLDAPFilter(filter.getNOTComponent(),
             currentIndentString + " !" + indentSpaces, indentSpaces,
             indentedFilterLines);
        indentedFilterLines.add(currentIndentString + " !)");
        break;


      default:
        indentedFilterLines.add(currentIndentString + filter.toString());
        break;
    }
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    examples.put(
         new String[]
         {
           "(|(givenName=jdoe)(|(sn=jdoe)(|(cn=jdoe)(|(uid=jdoe)(mail=jdoe)))))"
         },
         "Displays an indented representation of the provided filter, as " +
              "well as a simplified version of that filter.");

    return examples;
  }
}
