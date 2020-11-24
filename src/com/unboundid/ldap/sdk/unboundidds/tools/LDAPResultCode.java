/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020 Ping Identity Corporation
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
 * Copyright (C) 2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that can be used to list LDAP result
 * code names and their numeric values, or to search for result codes that match
 * a given name or value.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPResultCode
       extends CommandLineTool
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 2;



  // The argument used to indicate that the tool should list result codes in
  // alphabetic order rather than numeric order.
  @Nullable private BooleanArgument alphabeticOrderArg;

  // The argument used to indicate that the tool should list all defined result
  // codes.
  @Nullable private BooleanArgument listArg;

  // The argument used to indicate that the tool should generate tab-delimited
  // text output rather than as a table.
  @Nullable private BooleanArgument scriptFriendlyArg;

  // The argument used to indicate that the tool should search for the result
  // code with the specified integer value.
  @Nullable private IntegerArgument intValueArg;

  // The argument used to indicate that the tool should search for result coes
  // that have the specified string in thier name
  @Nullable private StringArgument searchArg;



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this program.  It may
   *               be empty, but must not be {@code null}.
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
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.  It may
   *               be empty, but must not be {@code null}.
   *
   * @return  A result code that indicates the result of tool processing.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDAPResultCode tool = new LDAPResultCode(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public LDAPResultCode(@Nullable final OutputStream out,
                        @Nullable final OutputStream err)
  {
    super(out, err);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldap-result-code";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDAP_RC_TOOL_DESC_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.singletonList(INFO_LDAP_RC_TOOL_DESC_2.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    listArg = new BooleanArgument('l', "list", 1,
         INFO_LDAP_RC_ARG_DESC_LIST.get());
    parser.addArgument(listArg);

    intValueArg = new IntegerArgument('i', "int-value", false, 1,
         INFO_LDAP_RC_ARG_PLACEHOLDER_INT_VALUE.get(),
         INFO_LDAP_RC_ARG_DESC_INT_VALUE.get());
    intValueArg.addLongIdentifier("intValue", true);
    parser.addArgument(intValueArg);

    searchArg = new StringArgument('S', "search", false, 1,
         INFO_LDAP_RC_ARG_PLACEHOLDER_SEARCH_STRING.get(),
         INFO_LDAP_RC_ARG_DESC_SEARCH.get());
    parser.addArgument(searchArg);

    alphabeticOrderArg = new BooleanArgument('a', "alphabetic-order", 1,
         INFO_LDAP_RC_ARG_DESC_ALPHABETIC.get());
    alphabeticOrderArg.addLongIdentifier("alphabeticOrder", true);
    alphabeticOrderArg.addLongIdentifier("alphabetical-order", true);
    alphabeticOrderArg.addLongIdentifier("alphabeticalOrder", true);
    alphabeticOrderArg.addLongIdentifier("alphabetic", true);
    alphabeticOrderArg.addLongIdentifier("alphabetical", true);
    parser.addArgument(alphabeticOrderArg);

    scriptFriendlyArg = new BooleanArgument(null, "script-friendly", 1,
         INFO_LDAP_RC_ARG_DESC_SCRIPT_FRIENDLY.get());
    scriptFriendlyArg.addLongIdentifier("scriptFriendly", true);
    parser.addArgument(scriptFriendlyArg);

    parser.addExclusiveArgumentSet(listArg, intValueArg, searchArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get all result codes that should be included in the output.
    final Map<Integer,ResultCode> resultCodesByIntValue = new TreeMap<>();
    final Map<String,ResultCode> resultCodesByName = new TreeMap<>();
    if ((intValueArg != null) && intValueArg.isPresent())
    {
      final int intValue = intValueArg.getValue();
      final ResultCode rc = ResultCode.valueOf(intValue, null, false);
      if (rc != null)
      {
        resultCodesByIntValue.put(intValue, rc);
        resultCodesByName.put(StaticUtils.toLowerCase(rc.getName()), rc);
      }
    }
    else
    {
      final String searchString;
      if ((searchArg != null) && searchArg.isPresent())
      {
        searchString = StaticUtils.toLowerCase(searchArg.getValue());
      }
      else
      {
        searchString = null;
      }

      for (final ResultCode rc : ResultCode.values())
      {
        final String name = rc.getName();
        final String lowerName = StaticUtils.toLowerCase(name);
        if (searchString != null)
        {
          if (! lowerName.contains(searchString))
          {
            continue;
          }
        }

        resultCodesByIntValue.put(rc.intValue(), rc);
        resultCodesByName.put(lowerName, rc);
      }
    }


    // If there weren't any matching result codes, then inform the user and
    // exit with an error.
    if (resultCodesByIntValue.isEmpty())
    {
      wrapErr(0, WRAP_COLUMN, ERR_LDAP_RC_NO_RESULTS.get());
      return ResultCode.NO_RESULTS_RETURNED;
    }


    // Iterate through the matching result codes and figure out how many
    // characters are in the longest name and
    final String nameLabel = INFO_LDAP_RC_NAME_LABEL.get();
    final String intValueLabel = INFO_LDAP_RC_INT_VALUE_LABEL.get();
    int numCharsInLongestName = nameLabel.length();
    int numCharsInLongestIntValue = intValueLabel.length();
    for (final Map.Entry<Integer,ResultCode> e :
         resultCodesByIntValue.entrySet())
    {
      final String intValueString = String.valueOf(e.getKey());
      numCharsInLongestIntValue =
           Math.max(numCharsInLongestIntValue, intValueString.length());

      final String name = e.getValue().getName();
      numCharsInLongestName = Math.max(numCharsInLongestName, name.length());
    }


    // Construct the column formatter that will be used to generate the output.
    final OutputFormat outputFormat;
    final boolean scriptFriendly =
         ((scriptFriendlyArg != null) && scriptFriendlyArg.isPresent());
    if (scriptFriendly)
    {
      outputFormat = OutputFormat.TAB_DELIMITED_TEXT;
    }
    else
    {
      outputFormat = OutputFormat.COLUMNS;
    }

    final ColumnFormatter formatter =
         new ColumnFormatter(false, null, outputFormat, " | ",
              new FormattableColumn(numCharsInLongestName,
                   HorizontalAlignment.LEFT, nameLabel),
              new FormattableColumn(numCharsInLongestIntValue,
                   HorizontalAlignment.LEFT, intValueLabel));


    // Display the table header, if appropriate.
    if (! scriptFriendly)
    {
      for (final String line : formatter.getHeaderLines(true))
      {
        out(line);
      }
    }


    // Display the table body.
    final Collection<ResultCode> resultCodes;
    if ((alphabeticOrderArg != null) && alphabeticOrderArg.isPresent())
    {
      resultCodes = resultCodesByName.values();
    }
    else
    {
      resultCodes = resultCodesByIntValue.values();
    }

    for (final ResultCode rc : resultCodes)
    {
      out(formatter.formatRow(rc.getName(), rc.intValue()));
    }

    return ResultCode.SUCCESS;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples = new LinkedHashMap<>();

    examples.put(
         StaticUtils.NO_STRINGS,
         INFO_LDAP_RC_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--int-value", "49",
           "--script-friendly"
         },
         INFO_LDAP_RC_EXAMPLE_2.get());

    examples.put(
         new String[]
         {
           "--search", "attribute"
         },
         INFO_LDAP_RC_EXAMPLE_3.get());

    return examples;
  }
}
