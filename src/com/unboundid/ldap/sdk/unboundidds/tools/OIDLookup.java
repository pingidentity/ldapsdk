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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.File;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OIDRegistry;
import com.unboundid.util.OIDRegistryItem;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that can be used to search the OID
 * registry to retrieve information an item with a specified OID or name.
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
public final class OIDLookup
       extends CommandLineTool
{
  /**
   * The column at which long lines of output should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The output format value that indicates that output should be generated as
   * comma-separated values.
   */
  @NotNull private static final String OUTPUT_FORMAT_CSV = "csv";



  /**
   * The output format value that indicates that output should be generated as
   * JSON objects.
   */
  @NotNull private static final String OUTPUT_FORMAT_JSON = "json";



  /**
   * The output format value that indicates that output should be generated as
   * multi-line text.
   */
  @NotNull private static final String OUTPUT_FORMAT_MULTI_LINE = "multi-line";



  /**
   * The output format value that indicates that output should be generated as
   * tab-delimited text.
   */
  @NotNull private static final String OUTPUT_FORMAT_TAB_DELIMITED =
       "tab-delimited";



  // The argument parser used by this tool.
  @Nullable private ArgumentParser parser;

  // The argument used to indicate that only exact matches should be returned.
  @Nullable private BooleanArgument exactMatchArg;

  // The argument used to request terse output.
  @Nullable private BooleanArgument terseArg;

  // The argument used to specify the path to an LDAP schema to use to augment
  // the default OID registry.
  @Nullable private FileArgument schemaPathArg;

  // The argument used to specify the output format.
  @Nullable private StringArgument outputFormatArg;



  /**
   * Invokes this tool with the provided set of command-line arguments.
   *
   * @param  args  The set of command-line arguments provided to this program.
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
   * Invokes this tool with the provided set of command-line arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The set of command-line arguments provided to this program.
   *
   * @return  A result code that indicates whether processing was successful.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final OIDLookup tool = new OIDLookup(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates an instance of this tool with the provided standard output and
   * error streams.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public OIDLookup(@Nullable final OutputStream out,
                   @Nullable final OutputStream err)
  {
    super(out, err);

    parser = null;
    exactMatchArg = null;
    terseArg = null;
    schemaPathArg = null;
    outputFormatArg = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "oid-lookup";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_OID_LOOKUP_TOOL_DESC_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.singletonList(INFO_OID_LOOKUP_TOOL_DESC_2.get());
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
  public int getMinTrailingArguments()
  {
    return 0;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return 1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return INFO_OID_LOOKUP_TRAILING_ARG_PLACEHOLDER.get();
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
    this.parser = parser;

    schemaPathArg = new FileArgument(null, "schema-path", false, 0, null,
         INFO_OID_LOOKUP_ARG_DESC_SCHEMA_PATH.get(), true, true, false, false);
    schemaPathArg.addLongIdentifier("schemaPath", true);
    schemaPathArg.addLongIdentifier("schema-file", true);
    schemaPathArg.addLongIdentifier("schemaFile", true);
    schemaPathArg.addLongIdentifier("schema-directory", true);
    schemaPathArg.addLongIdentifier("schemaDirectory", true);
    schemaPathArg.addLongIdentifier("schema-dir", true);
    schemaPathArg.addLongIdentifier("schemaDir", true);
    schemaPathArg.addLongIdentifier("schema", true);
    parser.addArgument(schemaPathArg);


    outputFormatArg = new StringArgument(null, "output-format", false, 1,
         INFO_OID_LOOKUP_ARG_PLACEHOLDER_OUTPUT_FORMAT.get(),
         INFO_OID_LOOKUP_ARG_DESC_OUTPUT_FORMAT.get(),
         StaticUtils.setOf(
              OUTPUT_FORMAT_CSV,
              OUTPUT_FORMAT_JSON,
              OUTPUT_FORMAT_MULTI_LINE,
              OUTPUT_FORMAT_TAB_DELIMITED),
         OUTPUT_FORMAT_MULTI_LINE);
    outputFormatArg.addLongIdentifier("outputFormat", true);
    outputFormatArg.addLongIdentifier("format", true);
    parser.addArgument(outputFormatArg);


    exactMatchArg = new BooleanArgument(null, "exact-match", 1,
         INFO_OID_LOOKUP_ARG_DESC_EXACT_MATCH.get());
    exactMatchArg.addLongIdentifier("exactMatch", true);
    exactMatchArg.addLongIdentifier("exact", true);
    parser.addArgument(exactMatchArg);


    terseArg = new BooleanArgument(null, "terse", 1,
         INFO_OID_LOOKUP_ARG_DESC_TERSE.get());
    parser.addArgument(terseArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get a reference to the default OID registry.
    OIDRegistry oidRegistry = OIDRegistry.getDefault();


    // If any schema paths were provided, then read the schema(s) and use that
    // to augment the default OID registry.  If not, and if this tool is running
    // from a Ping Identity Directory Server installation, then see if we can
    // use its default schema.
    List<File> schemaPaths = Collections.emptyList();
    if ((schemaPathArg != null) && (schemaPathArg.isPresent()))
    {
      schemaPaths = schemaPathArg.getValues();
    }
    else
    {
      try
      {
        final File instanceRoot = InternalSDKHelper.getPingIdentityServerRoot();
        if (instanceRoot != null)
        {
          final File instanceRootSchemaDir =
               StaticUtils.constructPath(instanceRoot, "config", "schema");
          if (new File(instanceRootSchemaDir, "00-core.ldif").exists())
          {
            schemaPaths = Collections.singletonList(instanceRootSchemaDir);
          }
        }
      }
      catch (final Throwable t)
      {
        // This is fine.  We're just not running with access to a Ping Identity
        // Directory Server.
      }
    }

    if (! schemaPaths.isEmpty())
    {
      try
      {
        oidRegistry = augmentOIDRegistry(oidRegistry, schemaPaths);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN, e.getMessage());
        return e.getResultCode();
      }
    }


    // See if there is a search string.  If so, then identify the appropriate
    // set of matching OID registry items.  Otherwise, just grab everything in
    // the OID registry.
    final Collection<OIDRegistryItem> matchingItems;
    if ((parser != null) && (! parser.getTrailingArguments().isEmpty()))
    {
      matchingItems = new ArrayList<>();
      final String lowerSearchString =
           StaticUtils.toLowerCase(parser.getTrailingArguments().get(0));
      for (final OIDRegistryItem item : oidRegistry.getItems().values())
      {
        if (itemMatchesSearchString(item, lowerSearchString,
             exactMatchArg.isPresent()))
        {
          matchingItems.add(item);
        }
      }
    }
    else
    {
      matchingItems = oidRegistry.getItems().values();
    }


    // If there weren't any matches, then display a message if appropriate.
    boolean json = false;
    ColumnFormatter columnFormatter = null;
    if ((outputFormatArg != null) && outputFormatArg.isPresent())
    {
      final String outputFormat = outputFormatArg.getValue();
      if (outputFormat != null)
      {
        if (outputFormat.equalsIgnoreCase(OUTPUT_FORMAT_CSV))
        {
          columnFormatter = new ColumnFormatter(false, null,
               OutputFormat.CSV, null,
               new FormattableColumn(1, HorizontalAlignment.LEFT, "OID"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Name"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Type"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Origin"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "URL"));
        }
        else if (outputFormat.equalsIgnoreCase(OUTPUT_FORMAT_JSON))
        {
          json = true;
        }
        else if (outputFormat.equalsIgnoreCase(OUTPUT_FORMAT_TAB_DELIMITED))
        {
          columnFormatter = new ColumnFormatter(false, null,
               OutputFormat.TAB_DELIMITED_TEXT, null,
               new FormattableColumn(1, HorizontalAlignment.LEFT, "OID"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Name"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Type"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "Origin"),
               new FormattableColumn(1, HorizontalAlignment.LEFT, "URL"));
        }
      }
    }


    final int numMatches = matchingItems.size();
    switch (numMatches)
    {
      case 0:
        wrapComment(WARN_OID_LOOKUP_NO_MATCHES.get());
        return ResultCode.NO_RESULTS_RETURNED;

      case 1:
        wrapComment(INFO_OID_LOOKUP_ONE_MATCH.get());
        break;

      default:
        wrapComment(INFO_OID_LOOKUP_MULTIPLE_MATCHES.get(numMatches));
        break;
    }


    if (columnFormatter != null)
    {
      for (final String line : columnFormatter.getHeaderLines(false))
      {
        out(line);
      }
    }


    for (final OIDRegistryItem item : matchingItems)
    {
      if (json)
      {
        out(item.asJSONObject().toSingleLineString());
      }
      else if (columnFormatter != null)
      {
        out(columnFormatter.formatRow(item.getOID(), item.getName(),
             item.getType(), item.getOrigin(), item.getURL()));
      }
      else
      {
        out();
        out(INFO_OID_LOOKUP_OUTPUT_LINE_OID.get(item.getOID()));
        out(INFO_OID_LOOKUP_OUTPUT_LINE_NAME.get(item.getName()));
        out(INFO_OID_LOOKUP_OUTPUT_LINE_TYPE.get(item.getType()));

        final String origin = item.getOrigin();
        if (origin != null)
        {
          out(INFO_OID_LOOKUP_OUTPUT_LINE_ORIGIN.get(origin));
        }

        final String url = item.getURL();
        if (url != null)
        {
          out(INFO_OID_LOOKUP_OUTPUT_LINE_URL.get(url));
        }
      }
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Retrieves a copy of the provided OID registry that has been augmented with
   * information read from a specified set of schema files.
   *
   * @param  registry     The OID registry to be augmented.
   * @param  schemaPaths  The paths containing the schema information to use to
   *                      augment the default registry.
   *
   * @return  The augmented OID registry.
   *
   * @throws  LDAPException  If a problem occurs while trying to read and parse
   *                         the schema.
   */
  @NotNull()
  private static OIDRegistry augmentOIDRegistry(
               @NotNull final OIDRegistry registry,
               @NotNull final List<File> schemaPaths)
          throws LDAPException
  {
    OIDRegistry oidRegistry = registry;
    for (final File schemaPath : schemaPaths)
    {
      if (schemaPath.isFile())
      {
        oidRegistry = augmentOIDRegistry(oidRegistry, schemaPath);
      }
      else if (schemaPath.isDirectory())
      {
        final File[] files = schemaPath.listFiles();
        if (files != null)
        {
          final TreeMap<String,File> fileMap = new TreeMap<>();
          for (final File f : files)
          {
            fileMap.put(f.getName(), f);
          }

          for (final File f : fileMap.values())
          {
            oidRegistry = augmentOIDRegistry(oidRegistry, f);
          }
        }
      }
    }

    return oidRegistry;
  }



  /**
   * Retrieves a copy of the provided OID registry that has been augmented with
   * information read from the specified schema file.
   *
   * @param  registry    The OID registry to be augmented.
   * @param  schemaFile  The file from which to read the schema elements.
   *
   * @return  The augmented OID registry.
   *
   * @throws  LDAPException  If a problem occurs while trying to read and parse
   *                         the schema.
 */
  @NotNull()
  private static OIDRegistry augmentOIDRegistry(
               @NotNull final OIDRegistry registry,
               @NotNull final File schemaFile)
          throws LDAPException
  {
    final Schema schema;
    try
    {
      schema = Schema.getSchema(schemaFile);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_OID_LOOKUP_CANNOT_GET_SCHEMA_FROM_FILE.get(
                schemaFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (schema == null)
    {
      return registry;
    }
    else
    {
      return registry.withSchema(schema);
    }
  }



  /**
   * Determines whether the provided OID registry item matches the given search
   * string.
   *
   * @param  item               The item for which to make the determination.
   * @param  lowerSearchString  The search string to match against the item.  It
   *                            must have already been converted to lowercase.
   * @param  exactMatch         Indicates whether to use exact matching (if
   *                            {@code true}) or substring matching (if
   *                            {@code false}).
   *
   * @return  {@code true} if the provided item matches the given search string,
   *          or {@code false} if not.
   */
  private static boolean itemMatchesSearchString(
               @NotNull final OIDRegistryItem item,
               @NotNull final String lowerSearchString,
               final boolean exactMatch)
  {
    return (matches(item.getOID(), lowerSearchString, exactMatch) ||
         matches(item.getName(), lowerSearchString, exactMatch) ||
         matches(item.getType(), lowerSearchString, exactMatch) ||
         matches(item.getOrigin(), lowerSearchString, exactMatch) ||
         matches(item.getURL(), lowerSearchString, exactMatch));
  }



  /**
   * Indicates whether the provided item matches the given search string.
   *
   * @param  itemString         A string from the registry item being
   *                            considered.  It may be {@code null}, and it may
   *                            be mixed-case.
   * @param  lowerSearchString  The search string to match against the item.  It
   *                            must have already been converted to lowercase.
   * @param  exactMatch         Indicates whether to use exact matching (if
   *                            {@code true}) or substring matching (if
   *                            {@code false}).
   *
   * @return  {@code true} if the provided item string matches the given search
   *          string, or {@code false} if not.
   */
  private static boolean matches(@Nullable final String itemString,
                                 @NotNull final String lowerSearchString,
                                 final boolean exactMatch)
  {
    if (itemString == null)
    {
      return false;
    }

    final String lowerItemString = StaticUtils.toLowerCase(itemString);
    if (exactMatch)
    {
      return lowerItemString.equals(lowerSearchString);
    }
    else
    {
      return lowerItemString.contains(lowerSearchString);
    }
  }



  /**
   * Writes a wrapped version of the provided message with each line preceded
   * by "# " to indicate that it is a comment.  No output will be written if the
   * tool is running in terse mode.
   *
   * @param  message  The message to write as a comment.
   */
  private void wrapComment(@NotNull final String message)
  {
    final boolean terse = ((terseArg != null) && terseArg.isPresent());
    if (! terse)
    {
      for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
      {
        out("# ", line);
      }
    }
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
         INFO_OID_LOOKUP_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--output-format", "json",
           "2.5.4.3"
         },
         INFO_OID_LOOKUP_EXAMPLE_2.get());

    return examples;
  }
}
