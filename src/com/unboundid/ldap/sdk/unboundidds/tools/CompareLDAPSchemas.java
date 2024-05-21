/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.AttributeSyntaxDefinition;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.DITContentRuleDefinition;
import com.unboundid.ldap.sdk.schema.DITStructureRuleDefinition;
import com.unboundid.ldap.sdk.schema.MatchingRuleDefinition;
import com.unboundid.ldap.sdk.schema.MatchingRuleUseDefinition;
import com.unboundid.ldap.sdk.schema.NameFormDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ExtendedSchemaInfoRequestControl;
import com.unboundid.util.Debug;
import com.unboundid.util.MultiServerLDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class implements a command-line tool that can be used to retrieve the
 * schemas from two LDAP servers and identify any differences between them.
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
 * <BR>
 * Comparisons that this tool may perform include:
 * <UL>
 *   <LI>Definitions that are present in one server but not another.</LI>
 *   <LI>Corresponding definitions with the same OID but different names or sets
 *       of names.</LI>
 *   <LI>Corresponding definitions with different descriptions, obsolete state,
 *       or sets of extensions.</LI>
 *   <LI>Corresponding attribute types with differences in syntaxes, matching
 *       rules, superior type, single-valued/multivalued behavior, usage,
 *       collective state, or NO-USER-MODIFICATION state.</LI>
 *   <LI>Corresponding object classes with differences in required or optional
 *       attributes, superior class, or object class type.</LI>
 *   <LI>Corresponding DIT content rules with differences in required, optional,
 *       or prohibited attributes, or allowed auxiliary classes.</LI>
 *   <LI>Corresponding name forms with differences in structural class,
 *       required attributes, or optional attributes.</LI>
 *   <LI>Corresponding DIT structure rules with different name form IDs or
 *       superior rule IDs.</LI>
 *   <LI>Corresponding matching rule uses with different sets of applicable
 *       attribute types.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CompareLDAPSchemas
       extends MultiServerLDAPCommandLineTool
{
  /**
   * The column at which long lines should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The index number used to reference the first server.
   */
  private static final int FIRST_SERVER_INDEX = 0;



  /**
   * The index number used to reference the second server.
   */
  private static final int SECOND_SERVER_INDEX = 1;



  /**
   * The name of the command-line argument used to indicate that the tool should
   * not examine schema elements that have an extension with a given name and
   * value.
   */
  @NotNull private static final String
       ARG_NAME_EXCLUDE_ELEMENTS_WITH_EXTENSION_VALUE =
            "excludeElementsWithExtensionValue";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * not examine schema elements with names matching a specified prefix.
   */
  @NotNull private static final String
       ARG_NAME_EXCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX =
            "excludeElementsWithNameMatchingPrefix";



  /**
   * The name of the command-line argument used to specify the DN of the first
   * server's subschema subentry.
   */
  @NotNull private static final String ARG_NAME_FIRST_SCHEMA_ENTRY_DN =
       "firstSchemaEntryDN";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * use the get extended schema info request control if the server reports that
   * it is supported.
   */
  @NotNull private static final String ARG_NAME_GET_EXTENDED_SCHEMA_INFO =
       "getExtendedSchemaInfo";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * ignore differences in element descriptions.
   */
  @NotNull private static final String ARG_NAME_IGNORE_DESCRIPTIONS =
       "ignoreDescriptions";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * ignore differences in element extensions.
   */
  @NotNull private static final String ARG_NAME_IGNORE_EXTENSIONS =
       "ignoreExtensions";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * only examine schema elements that have an extension with a given name and
   * value.
   */
  @NotNull private static final String
       ARG_NAME_INCLUDE_ELEMENTS_WITH_EXTENSION_VALUE =
            "includeElementsWithExtensionValue";



  /**
   * The name of the command-line argument used to indicate that the tool should
   * only examine schema elements with names matching a specified prefix.
   */
  @NotNull private static final String
       ARG_NAME_INCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX =
            "includeElementsWithNameMatchingPrefix";



  /**
   * The name of the command-line argument used to specify the types of schema
   * elements that the server should examine.
   */
  @NotNull private static final String ARG_NAME_SCHEMA_ELEMENT_TYPE =
       "schemaElementType";



  /**
   * The name of the command-line argument used to specify the DN of the second
   * server's subschema subentry.
   */
  @NotNull private static final String ARG_NAME_SECOND_SCHEMA_ENTRY_DN =
       "secondSchemaEntryDN";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine attribute syntaxes.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES =
       "attribute-syntaxes";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine attribute types.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES =
       "attribute-types";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine DIT content rules.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES =
       "dit-content-rules";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine DIT structure rules.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES =
       "dit-structure-rules";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine matching rule uses.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES =
       "matching-rule-uses";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine matching rules.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_MATCHING_RULES =
       "matching-rules";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine object classes.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES =
       "object-classes";



  /**
   * The name of the schema element type value that indicates that the tool
   * should examine name forms.
   */
  @NotNull private static final String SCHEMA_ELEMENT_TYPE_NAME_FORMS =
       "name-forms";



  // A reference to the argument parser for this tool.
  @NotNull private final AtomicReference<ArgumentParser> parserRef;

  // A reference to the completion message for this tool.
  @NotNull private final AtomicReference<String> completionMessageRef;

  // Indicates whether to ignore differences in schema element descriptions.
  private boolean ignoreDescriptions;

  // Indicates whether to ignore differences in schema element extensions.
  private boolean ignoreExtensions;

  // Indicates whether we may include or exclude schema elements based on their
  // extensions.
  private boolean includeOrExcludeBasedOnExtensions;

  // Indicates whether we may include or exclude schema elements based on their
  // name.
  private boolean includeOrExcludeBasedOnName;

  // A list of name prefixes for schema elements to exclude from the comparison.
  @NotNull private final List<String> excludeNamePrefixes;

  // A list of name prefixes for schema elements to include in the comparison.
  @NotNull private final List<String> includeNamePrefixes;

  // A map of schema extension values for schema elements to exclude from the
  // comparison.
  @NotNull private final Map<String,List<String>> excludeExtensionValues;

  // A map of schema extension values for schema elements to include in the
  // comparison.
  @NotNull private final Map<String,List<String>> includeExtensionValues;

  // The set of schema element types to examine.
  @NotNull private final Set<String> schemaElementTypes;



  /**
   * Runs this tool with the provided set of arguments, using the default
   * streams for standard output and standard error.
   *
   * @param  args  The command-line arguments to use to run this program.  It
   *               must not be {@code null}, but may be empty.
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
   * Runs this tool with the provided set of arguments, using the provided
   * streams for standard output and standard error.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments to use to run this program.  It
   *               must not be {@code null}, but may be empty.
   *
   * @return  The result code with information about the result of processing.
   *          A result code of {@code SUCCESS} indicates that all processing
   *          completed successfully and no differences were identified.  A
   *          result code of {@code COMPARE_FALSE} indicates that all processing
   *          completed successfully, but one or more differences were
   *          identified between the server schemas.  Any other result code
   *          indicates that some problem occurred during processing.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final CompareLDAPSchemas tool = new CompareLDAPSchemas(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided streams for standard
   * output and standard error.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public CompareLDAPSchemas(@Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    super(out, err, new String[] { "first", "second" }, null);

    parserRef = new AtomicReference<>();
    completionMessageRef = new AtomicReference<>();

    schemaElementTypes = new HashSet<>(StaticUtils.setOf(
         SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES,
         SCHEMA_ELEMENT_TYPE_MATCHING_RULES,
         SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES,
         SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES,
         SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES,
         SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES,
         SCHEMA_ELEMENT_TYPE_NAME_FORMS,
         SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES));

    ignoreDescriptions = false;
    ignoreExtensions = false;
    includeNamePrefixes = new ArrayList<>();
    excludeNamePrefixes = new ArrayList<>();
    includeExtensionValues = new HashMap<>();
    excludeExtensionValues = new HashMap<>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "compare-ldap-schemas";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_COMPARE_SCHEMA_TOOL_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.getNumericVersionString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    parserRef.set(parser);

    final DNArgument firstSchemaEntryDNArg = new DNArgument(null,
         ARG_NAME_FIRST_SCHEMA_ENTRY_DN, false, 1, null,
         INFO_COMPARE_SCHEMA_ARG_DESC_FIRST_SCHEMA_ENTRY_DN.get());
    firstSchemaEntryDNArg.addLongIdentifier("first-schema-entry-dn", true);
    firstSchemaEntryDNArg.addLongIdentifier("firstSchemaEntry", true);
    firstSchemaEntryDNArg.addLongIdentifier("first-schema-entry", true);
    firstSchemaEntryDNArg.addLongIdentifier("firstSchemaDN", true);
    firstSchemaEntryDNArg.addLongIdentifier("first-schema-dn", true);
    firstSchemaEntryDNArg.addLongIdentifier("firstSchema", true);
    firstSchemaEntryDNArg.addLongIdentifier("first-schema", true);
    parser.addArgument(firstSchemaEntryDNArg);

    final DNArgument secondSchemaEntryDNArg = new DNArgument(null,
         ARG_NAME_SECOND_SCHEMA_ENTRY_DN, false, 1, null,
         INFO_COMPARE_SCHEMA_ARG_DESC_SECOND_SCHEMA_ENTRY_DN.get());
    secondSchemaEntryDNArg.addLongIdentifier("second-schema-entry-dn", true);
    secondSchemaEntryDNArg.addLongIdentifier("secondSchemaEntry", true);
    secondSchemaEntryDNArg.addLongIdentifier("second-schema-entry", true);
    secondSchemaEntryDNArg.addLongIdentifier("secondSchemaDN", true);
    secondSchemaEntryDNArg.addLongIdentifier("second-schema-dn", true);
    secondSchemaEntryDNArg.addLongIdentifier("secondSchema", true);
    secondSchemaEntryDNArg.addLongIdentifier("second-schema", true);
    parser.addArgument(secondSchemaEntryDNArg);

    final StringArgument schemaElementTypesArg = new StringArgument(null,
         ARG_NAME_SCHEMA_ELEMENT_TYPE, false, 0,
         INFO_COMPARE_SCHEMA_ARG_PLACEHOLDER_SCHEMA_ELEMENT_TYPE.get(),
         INFO_COMPARE_SCHEMA_ARG_DESC_SCHEMA_ELEMENT_TYPE.get(
              SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES,
              SCHEMA_ELEMENT_TYPE_MATCHING_RULES,
              SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES,
              SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES,
              SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES,
              SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES,
              SCHEMA_ELEMENT_TYPE_NAME_FORMS,
              SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES));
    schemaElementTypesArg.addLongIdentifier("schema-element-types", true);
    parser.addArgument(schemaElementTypesArg);

    final BooleanArgument getExtendedSchemaInfoArg = new BooleanArgument(null,
         ARG_NAME_GET_EXTENDED_SCHEMA_INFO, 1,
         INFO_COMPARE_SCHEMA_ARG_DESC_GET_EXTENDED_SCHEMA_INFO.get());
    getExtendedSchemaInfoArg.addLongIdentifier("get-extended-schema-info",
         true);
    parser.addArgument(getExtendedSchemaInfoArg);

    final BooleanArgument ignoreDescriptionsArg = new BooleanArgument(null,
         ARG_NAME_IGNORE_DESCRIPTIONS, 1,
         INFO_COMPARE_SCHEMA_ARG_DESC_IGNORE_DESCRIPTIONS.get());
    ignoreDescriptionsArg.addLongIdentifier("ignore-descriptions", true);
    ignoreDescriptionsArg.addLongIdentifier("ignoreDescription", true);
    ignoreDescriptionsArg.addLongIdentifier("ignore-description", true);
    parser.addArgument(ignoreDescriptionsArg);

    final BooleanArgument ignoreExtensionsArg = new BooleanArgument(null,
         ARG_NAME_IGNORE_EXTENSIONS, 1,
         INFO_COMPARE_SCHEMA_ARG_DESC_IGNORE_EXTENSIONS.get());
    ignoreExtensionsArg.addLongIdentifier("ignore-extensions", true);
    ignoreExtensionsArg.addLongIdentifier("ignoreExtension", true);
    ignoreExtensionsArg.addLongIdentifier("ignore-extension", true);
    parser.addArgument(ignoreExtensionsArg);

    final StringArgument includeElementsWithNameMatchingPrefixArg =
         new StringArgument(null,
              ARG_NAME_INCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX, false, 0,
              INFO_COMPARE_SCHEMA_ARG_PLACEHOLDER_PREFIX.get(),
              INFO_COMPARE_SCHEMA_ARG_DESC_INCLUDE_NAME_MATCHING_PREFIX.get());
    includeElementsWithNameMatchingPrefixArg.addLongIdentifier(
         "include-elements-with-name-matching-prefix", true);
    parser.addArgument(includeElementsWithNameMatchingPrefixArg);

    final StringArgument excludeElementsWithNameMatchingPrefixArg =
         new StringArgument(null,
              ARG_NAME_EXCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX, false, 0,
              INFO_COMPARE_SCHEMA_ARG_PLACEHOLDER_PREFIX.get(),
              INFO_COMPARE_SCHEMA_ARG_DESC_EXCLUDE_NAME_MATCHING_PREFIX.get());
    excludeElementsWithNameMatchingPrefixArg.addLongIdentifier(
         "exclude-elements-with-name-matching-prefix", true);
    parser.addArgument(excludeElementsWithNameMatchingPrefixArg);

    final StringArgument includeElementsWithExtensionValueArg =
         new StringArgument(null,
              ARG_NAME_INCLUDE_ELEMENTS_WITH_EXTENSION_VALUE, false, 0,
              INFO_COMPARE_SCHEMA_ARG_PLACEHOLDER_EXTENSION_VALUE.get(),
              INFO_COMPARE_SCHEMA_ARG_DESC_INCLUDE_EXTENSION_VALUE.get());
    includeElementsWithExtensionValueArg.addLongIdentifier(
         "include-elements-with-extension-value", true);
    parser.addArgument(includeElementsWithExtensionValueArg);

    final StringArgument excludeElementsWithExtensionValueArg =
         new StringArgument(null,
              ARG_NAME_EXCLUDE_ELEMENTS_WITH_EXTENSION_VALUE, false, 0,
              INFO_COMPARE_SCHEMA_ARG_PLACEHOLDER_EXTENSION_VALUE.get(),
              INFO_COMPARE_SCHEMA_ARG_DESC_EXCLUDE_EXTENSION_VALUE.get());
    excludeElementsWithExtensionValueArg.addLongIdentifier(
         "exclude-elements-with-extension-value", true);
    parser.addArgument(excludeElementsWithExtensionValueArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // Identify the types of schema elements to examine.
    final ArgumentParser parser = parserRef.get();
    final StringArgument schemaElementTypesArg =
         parser.getStringArgument(ARG_NAME_SCHEMA_ELEMENT_TYPE);
    if ((schemaElementTypesArg != null) && schemaElementTypesArg.isPresent())
    {
      schemaElementTypes.clear();
      for (final String value : schemaElementTypesArg.getValues())
      {
        if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_MATCHING_RULES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_MATCHING_RULES);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES);
        }
        else if (value.equalsIgnoreCase(
             SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_NAME_FORMS))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_NAME_FORMS);
        }
        else if (value.equalsIgnoreCase(SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES))
        {
          schemaElementTypes.add(SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES);
        }
        else
        {
          throw new ArgumentException(
               ERR_COMPARE_SCHEMA_INVALID_SCHEMA_ELEMENT_TYPE.get(value,
                    ARG_NAME_SCHEMA_ELEMENT_TYPE,
                    SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES,
                    SCHEMA_ELEMENT_TYPE_MATCHING_RULES,
                    SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES,
                    SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES,
                    SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES,
                    SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES,
                    SCHEMA_ELEMENT_TYPE_NAME_FORMS,
                    SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES));
        }
      }
    }


    // Determine whether to ignore schema element descriptions or extensions.
    final BooleanArgument ignoreDescriptionsArg =
         parser.getBooleanArgument(ARG_NAME_IGNORE_DESCRIPTIONS);
    ignoreDescriptions =
         ((ignoreDescriptionsArg != null) && ignoreDescriptionsArg.isPresent());

    final BooleanArgument ignoreExtensionsArg =
         parser.getBooleanArgument(ARG_NAME_IGNORE_EXTENSIONS);
    ignoreExtensions =
         ((ignoreExtensionsArg != null) && ignoreExtensionsArg.isPresent());


    // Identify the schema element name prefixes to include and exclude.
    getNamePrefixes(ARG_NAME_INCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX,
         includeNamePrefixes);
    getNamePrefixes(ARG_NAME_EXCLUDE_ELEMENTS_WITH_NAME_MATCHING_PREFIX,
         excludeNamePrefixes);
    includeOrExcludeBasedOnName = (! includeNamePrefixes.isEmpty()) ||
         (! excludeNamePrefixes.isEmpty());


    // Identify the schema element extension values to include and exclude.
    getExtensionValues(ARG_NAME_INCLUDE_ELEMENTS_WITH_EXTENSION_VALUE,
         includeExtensionValues);
    getExtensionValues(ARG_NAME_EXCLUDE_ELEMENTS_WITH_EXTENSION_VALUE,
         excludeExtensionValues);
    includeOrExcludeBasedOnExtensions = (! includeExtensionValues.isEmpty()) ||
         (! excludeExtensionValues.isEmpty());
  }



  /**
   * Populates the provided list with the set of schema element prefixes
   * contained in the specified argument.
   *
   * @param  argumentName  The name of the argument whose values will be used to
   *                       populate the given list.
   * @param  prefixList    The list to be updated to include the values of the
   *                       specified argument.
   */
  private void getNamePrefixes(@NotNull final String argumentName,
                               @NotNull final List<String> prefixList)
  {
    prefixList.clear();
    final StringArgument arg = parserRef.get().getStringArgument(argumentName);
    if ((arg == null) || (! arg.isPresent()))
    {
      return;
    }

    for (final String value : arg.getValues())
    {
      prefixList.add(StaticUtils.toLowerCase(value));
    }
  }



  /**
   * Populates the provided map with the set of schema element extension
   * name-value pairs contained in the specified argument.
   *
   * @param  argumentName  The name of the argument whose values will be used to
   *                       populate the given map.
   * @param  extensionMap  The map to be updated to include the values of the
   *                       specified argument.
   *
   * @throws  ArgumentException  If there is a problem with any of the values of
   *                             the specified argument.
   */
  private void getExtensionValues(
                    @NotNull final String argumentName,
                    @NotNull final Map<String,List<String>> extensionMap)
          throws ArgumentException
  {
    extensionMap.clear();
    final StringArgument arg = parserRef.get().getStringArgument(argumentName);
    if ((arg == null) || (! arg.isPresent()))
    {
      return;
    }

    for (final String value : arg.getValues())
    {
      final int equalPos = value.indexOf('=');
      if (equalPos < 0)
      {
        throw new ArgumentException(
             ERR_COMPARE_SCHEMA_EXTENSION_VALUE_NO_EQUALS.get(argumentName,
                  value));
      }

      final String extensionName =
           StaticUtils.toLowerCase(value.substring(0, equalPos));
      if (extensionName.isEmpty())
      {
        throw new ArgumentException(
             ERR_COMPARE_SCHEMA_EXTENSION_VALUE_EMPTY_NAME.get(argumentName,
                  value));
      }

      final String extensionValue =
           StaticUtils.toLowerCase(value.substring(equalPos + 1));
      if (extensionValue.isEmpty())
      {
        throw new ArgumentException(
             ERR_COMPARE_SCHEMA_EXTENSION_VALUE_EMPTY_VALUE.get(argumentName,
                  value));
      }

      List<String> valueList = extensionMap.get(extensionName);
      if (valueList == null)
      {
        valueList = new ArrayList<>();
        extensionMap.put(extensionName, valueList);
      }

      valueList.add(extensionValue);
    }
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
    return true;
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
  protected boolean supportsDebugLogging()
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
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return completionMessageRef.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the schemas from each of the servers.
    final Schema firstServerSchema;
    final Map<String,LDAPException> firstUnparsableAttributeSyntaxes =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableMatchingRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableAttributeTypes =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableObjectClasses =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableDITContentRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableDITStructureRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableNameForms =
         new LinkedHashMap<>();
    final Map<String,LDAPException> firstUnparsableMatchingRuleUses =
         new LinkedHashMap<>();
    try
    {
      firstServerSchema = getSchema(FIRST_SERVER_INDEX,
           ARG_NAME_FIRST_SCHEMA_ENTRY_DN,
           INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
           firstUnparsableAttributeSyntaxes, firstUnparsableMatchingRules,
           firstUnparsableAttributeTypes, firstUnparsableObjectClasses,
           firstUnparsableDITContentRules, firstUnparsableDITStructureRules,
           firstUnparsableNameForms, firstUnparsableMatchingRuleUses);
    }
    catch (final LDAPException e)
    {
      logCompletionError(e.getMessage());
      return e.getResultCode();
    }

    final Schema secondServerSchema;
    final Map<String,LDAPException> secondUnparsableAttributeSyntaxes =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableMatchingRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableAttributeTypes =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableObjectClasses =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableDITContentRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableDITStructureRules =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableNameForms =
         new LinkedHashMap<>();
    final Map<String,LDAPException> secondUnparsableMatchingRuleUses =
         new LinkedHashMap<>();
    try
    {
      secondServerSchema = getSchema(SECOND_SERVER_INDEX,
           ARG_NAME_SECOND_SCHEMA_ENTRY_DN,
           INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
           secondUnparsableAttributeSyntaxes, secondUnparsableMatchingRules,
           secondUnparsableAttributeTypes, secondUnparsableObjectClasses,
           secondUnparsableDITContentRules, secondUnparsableDITStructureRules,
           secondUnparsableNameForms, secondUnparsableMatchingRuleUses);
    }
    catch (final LDAPException e)
    {
      logCompletionError(e.getMessage());
      return e.getResultCode();
    }


    // Report on any unparsable schema elements.
    final AtomicReference<ResultCode> resultCodeRef = new AtomicReference<>();
    boolean unparsableElementsEncountered = reportUnparsableSchemaElements(
         INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
         firstUnparsableAttributeSyntaxes, firstUnparsableMatchingRules,
         firstUnparsableAttributeTypes, firstUnparsableObjectClasses,
         firstUnparsableDITContentRules, firstUnparsableDITStructureRules,
         firstUnparsableNameForms, firstUnparsableMatchingRuleUses);

    unparsableElementsEncountered |= reportUnparsableSchemaElements(
         INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
         secondUnparsableAttributeSyntaxes, secondUnparsableMatchingRules,
         secondUnparsableAttributeTypes, secondUnparsableObjectClasses,
         secondUnparsableDITContentRules, secondUnparsableDITStructureRules,
         secondUnparsableNameForms, secondUnparsableMatchingRuleUses);

    if (unparsableElementsEncountered)
    {
      resultCodeRef.set(ResultCode.INVALID_ATTRIBUTE_SYNTAX);
    }


    // Validate the different types of schema elements.
    final AtomicInteger numDifferences = new AtomicInteger();
    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES))
    {
      compareAttributeSyntaxes(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_MATCHING_RULES))
    {
      compareMatchingRules(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES))
    {
      compareAttributeTypes(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES))
    {
      compareObjectClasses(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES))
    {
      compareDITContentRules(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES))
    {
      compareDITStructureRules(firstServerSchema, secondServerSchema,
           numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_NAME_FORMS))
    {
      compareNameForms(firstServerSchema, secondServerSchema, numDifferences);
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES))
    {
      compareMatchingRuleUses(firstServerSchema, secondServerSchema,
           numDifferences);
    }


    // If any errors were encountered, then return an error result code.
    // Otherwise, if any differences were encountered, then return a
    // COMPARE_FALSE result code.  Otherwise, return a SUCCESS result code.
    final int differenceCount = numDifferences.get();
    if (unparsableElementsEncountered)
    {
      switch (differenceCount)
      {
        case 0:
          logCompletionError(
               ERR_COMPARE_SCHEMA_SUMMARY_UNPARSABLE_NO_DIFFERENCES.get());
          break;
        case 1:
          logCompletionError(
               ERR_COMPARE_SCHEMA_SUMMARY_UNPARSABLE_WITH_DIFFERENCE.get());
          break;
        default:
          logCompletionError(
               ERR_COMPARE_SCHEMA_SUMMARY_UNPARSABLE_WITH_DIFFERENCES.get(
                    differenceCount));
          break;
      }
    }
    else if (differenceCount > 0)
    {
      resultCodeRef.compareAndSet(null, ResultCode.COMPARE_FALSE);
      if (differenceCount == 1)
      {
        logCompletionError(
             ERR_COMPARE_SCHEMA_SUMMARY_DIFFERENCE.get());
      }
      else
      {
        logCompletionError(
             ERR_COMPARE_SCHEMA_SUMMARY_DIFFERENCES.get(differenceCount));
      }
    }
    else
    {
      resultCodeRef.compareAndSet(null, ResultCode.SUCCESS);
      final String message = INFO_COMPARE_SCHEMA_SUMMARY_NO_DIFFERENCES.get();
      completionMessageRef.compareAndSet(null, message);
      wrapOut(0, WRAP_COLUMN, message);
    }

    return resultCodeRef.get();
  }



  /**
   * Retrieves the schema from the specified server.
   *
   * @param  serverIndex
   *              The index for the server from which to retrieve the schema.
   * @param  schemaDNArgName
   *              The name of the argument to use to retrieve the DN of the
   *              subschema subentry, if specified.  It must not be
   *              {@code null}.
   * @param  serverLabel
   *              The label to use to refer to the server.  It must not be
   *              {@code null}.
   * @param  unparsableAttributeSyntaxes
   *              A map that will be updated with information about any
   *              unparsable attribute syntax definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableMatchingRules
   *              A map that will be updated with information about any
   *              unparsable matching rule definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableAttributeTypes
   *              A map that will be updated with information about any
   *              unparsable attribute type definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableObjectClasses
   *              A map that will be updated with information about any
   *              unparsable object class definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableDITContentRules
   *              A map that will be updated with information about any
   *              unparsable DIT content rule definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableDITStructureRules
   *              A map that will be updated with information about any
   *              unparsable DIT structure rule definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableNameForms
   *              A map that will be updated with information about any
   *              unparsable name form definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   * @param  unparsableMatchingRuleUses
   *              A map that will be updated with information about any
   *              unparsable matching rule use definitions found in the schema
   *              from the specified server.  Each key will be the unparsable
   *              definition, and the corresponding value will be the exception
   *              caught while trying to parse it.  It must not be {@code null}.
   *
   * @return  The schema retrieved from the server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to obtain the
   *                         schema.
   */
  @NotNull()
  private Schema getSchema(final int serverIndex,
       @NotNull final String schemaDNArgName,
       @NotNull final String serverLabel,
       @NotNull final Map<String,LDAPException> unparsableAttributeSyntaxes,
       @NotNull final Map<String,LDAPException> unparsableMatchingRules,
       @NotNull final Map<String,LDAPException> unparsableAttributeTypes,
       @NotNull final Map<String,LDAPException> unparsableObjectClasses,
       @NotNull final Map<String,LDAPException> unparsableDITContentRules,
       @NotNull final Map<String,LDAPException> unparsableDITStructureRules,
       @NotNull final Map<String,LDAPException> unparsableNameForms,
       @NotNull final Map<String,LDAPException> unparsableMatchingRuleUses)
       throws LDAPException
  {
    // Establish a connection to the server.
    final LDAPConnection conn;
    try
    {
      conn = getConnection(serverIndex);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(e.getResultCode(),
           ERR_COMPARE_SCHEMA_CANNOT_CONNECT.get(serverLabel, e.getMessage()),
           e);
    }

    final ArgumentParser parser = parserRef.get();
    final BooleanArgument getExtendedSchemaInfoArg =
         parser.getBooleanArgument(ARG_NAME_GET_EXTENDED_SCHEMA_INFO);
    final boolean getExtendedSchemaInfo =
         ((getExtendedSchemaInfoArg != null) &&
              getExtendedSchemaInfoArg.isPresent());


    try
    {
      // See if the schema entry DN was specified as an argument.  If so, then
      // retrieve that entry and parse it as a schema entry.  Otherwise, use the
      // default method for obtaining the schema.
      final String schemaEntryDN;
      final DNArgument schemaEntryDNArg = parser.getDNArgument(schemaDNArgName);
      if (schemaEntryDNArg.isPresent())
      {
        schemaEntryDN = schemaEntryDNArg.getStringValue();
      }
      else
      {
        final RootDSE rootDSE = conn.getRootDSE();
        if (rootDSE == null)
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_COMPARE_SCHEMA_CANNOT_GET_ROOT_DSE.get(serverLabel));
        }

        schemaEntryDN = rootDSE.getSubschemaSubentryDN();
        if (schemaEntryDN == null)
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_COMPARE_SCHEMA_CANNOT_GET_ROOT_DSE_SCHEMA_DN.get(serverLabel,
                    RootDSE.ATTR_SUBSCHEMA_SUBENTRY));
        }
      }

      final SearchRequest searchRequest = new SearchRequest(schemaEntryDN,
           SearchScope.BASE, Schema.SUBSCHEMA_SUBENTRY_FILTER,
           Schema.SCHEMA_REQUEST_ATTRS);
      if (getExtendedSchemaInfo)
      {
        searchRequest.addControl(new ExtendedSchemaInfoRequestControl(false));
      }

      final Entry schemaEntry = conn.searchForEntry(searchRequest);
      if (schemaEntry == null)
      {
        throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
             ERR_COMPARE_SCHEMA_CANNOT_GET_SCHEMA_ENTRY.get(
                  String.valueOf(schemaEntryDN), serverLabel));
      }

      return new Schema(schemaEntry, unparsableAttributeSyntaxes,
           unparsableMatchingRules, unparsableAttributeTypes,
           unparsableObjectClasses, unparsableDITContentRules,
           unparsableDITStructureRules, unparsableNameForms,
           unparsableMatchingRuleUses);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(e.getResultCode(),
           ERR_COMPARE_SCHEMA_CANNOT_GET_SCHEMA.get(serverLabel,
                e.getMessage()),
           e);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Reports error messages about any unparsable elements found in a server's
   * schema.
   *
   * @param  serverLabel
   *              The label for the associated directory server instance.
   * @param  unparsableAttributeSyntaxes
   *              A map with information about any unparsable attribute syntax
   *              definitions found in the schema.
   * @param  unparsableMatchingRules
   *              A map with information about any unparsable matching rule
   *              definitions found in the schema.
   * @param  unparsableAttributeTypes
   *              A map with information about any unparsable attribute type
   *              definitions found in the schema.
   * @param  unparsableObjectClasses
   *              A map with information about any unparsable object class
   *              definitions found in the schema.
   * @param  unparsableDITContentRules
   *              A map with information about any unparsable DIT content rule
   *              definitions found in the schema.
   * @param  unparsableDITStructureRules
   *              A map with information about any unparsable DIT structure rule
   *              definitions found in the schema.
   * @param  unparsableNameForms
   *              A map with information about any unparsable name form
   *              definitions found in the schema.
   * @param  unparsableMatchingRuleUses
   *              A map with information about any unparsable matching rule use
   *              definitions found in the schema.
   *
   * @return  {@code true} if the schema contained any unparsable elements, or
   *          {@code false} if not.
   */
  private boolean reportUnparsableSchemaElements(
       @NotNull final String serverLabel,
       @NotNull final Map<String,LDAPException> unparsableAttributeSyntaxes,
       @NotNull final Map<String,LDAPException> unparsableMatchingRules,
       @NotNull final Map<String,LDAPException> unparsableAttributeTypes,
       @NotNull final Map<String,LDAPException> unparsableObjectClasses,
       @NotNull final Map<String,LDAPException> unparsableDITContentRules,
       @NotNull final Map<String,LDAPException> unparsableDITStructureRules,
       @NotNull final Map<String,LDAPException> unparsableNameForms,
       @NotNull final Map<String,LDAPException> unparsableMatchingRuleUses)
  {
    boolean unparsableFound = false;

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAXES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableAttributeSyntaxes,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAX.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_MATCHING_RULES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableMatchingRules,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableAttributeTypes,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_OBJECT_CLASSES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableObjectClasses,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableDITContentRules,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableDITStructureRules,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_NAME_FORMS))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableNameForms,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get());
    }

    if (schemaElementTypes.contains(SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USES))
    {
      unparsableFound |= reportUnparsableSchemaElements(serverLabel,
           unparsableMatchingRuleUses,
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get());
    }

    return unparsableFound;
  }



  /**
   * Reports error messages about any unparsable elements of the specified type
   * found in a server's schema.
   *
   * @param  serverLabel         The label for the associated directory server
   *                             instance.  It must not be {@code null}.
   * @param  unparsableElements  The set of unparsable elements of a given type.
   *                             It must not be {@code null}, but may be empty.
   * @param  elementTypeName     The name of the schema element type.  It must
   *                             not be {@code null}.
   *
   * @return  {@code true} if the provided map contained information about one
   *          or more unparsable elements, or {@code false} if not.
   */
  private boolean reportUnparsableSchemaElements(
       @NotNull final String serverLabel,
       @NotNull final Map<String,LDAPException> unparsableElements,
       @NotNull final String elementTypeName)
  {
    for (final Map.Entry<String,LDAPException> e :
         unparsableElements.entrySet())
    {
      wrapErr(0, WRAP_COLUMN,
           ERR_COMPARE_SCHEMA_UNPARSABLE_ELEMENT.get(elementTypeName,
                serverLabel, e.getValue().getMessage()));
      err(e.getKey());
      err();
    }

    return (! unparsableElements.isEmpty());
  }



  /**
   * Compares the attribute syntax definitions contained in the provided
   * schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareAttributeSyntaxes(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the attribute syntax definitions from each of the schemas.
    final Map<OID,AttributeSyntaxDefinition> syntaxes1 =
         getAttributeSyntaxMap(firstServerSchema);
    final Map<OID,AttributeSyntaxDefinition> syntaxes2 =
         getAttributeSyntaxMap(secondServerSchema);


    // Identify syntaxes that exist in one server but not another.  If any are
    // found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,AttributeSyntaxDefinition>> iterator =
         syntaxes1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,AttributeSyntaxDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! syntaxes2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_SYNTAX.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = syntaxes2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,AttributeSyntaxDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! syntaxes1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_SYNTAX.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining syntaxes should exist in both servers.  Compare them and
    // see if there are any differences between them.
    for (final OID oid : syntaxes1.keySet())
    {
      final AttributeSyntaxDefinition d1 = syntaxes1.get(oid);
      final AttributeSyntaxDefinition d2 = syntaxes2.get(oid);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAX.get(),
             oid.toString(),
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAX.get(),
           oid.toString(), d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the attribute syntax definitions contained in the
   * provided schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the attribute syntaxes.
   *                 It must not be {@code null}.
   *
   * @return  A map of the attribute syntax definitions contained in the
   *          provided schema.
   */
  @NotNull()
  private Map<OID,AttributeSyntaxDefinition> getAttributeSyntaxMap(
               @NotNull final Schema schema)
  {
    final Map<OID,AttributeSyntaxDefinition> syntaxes = new TreeMap<>();
    for (final AttributeSyntaxDefinition d : schema.getAttributeSyntaxes())
    {
      if (includeBasedOnNameAndExtensions(StaticUtils.NO_STRINGS,
           d.getExtensions()))
      {
        syntaxes.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return syntaxes;
  }



  /**
   * Compares the matching rule definitions contained in the provided schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareMatchingRules(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the matching rule definitions from each of the schemas.
    final Map<OID,MatchingRuleDefinition> matchingRules1 =
         getMatchingRuleMap(firstServerSchema);
    final Map<OID,MatchingRuleDefinition> matchingRules2 =
         getMatchingRuleMap(secondServerSchema);


    // Identify matching rules that exist in one server but not another.  If any
    // are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,MatchingRuleDefinition>> iterator =
         matchingRules1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,MatchingRuleDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! matchingRules2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_MATCHING_RULE.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
        e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = matchingRules2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,MatchingRuleDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! matchingRules1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_MATCHING_RULE.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining matching rules should exist in both servers.  Compare them
    // and see if there are any differences between them.
    for (final OID oid : matchingRules1.keySet())
    {
      final MatchingRuleDefinition d1 = matchingRules1.get(oid);
      final MatchingRuleDefinition d2 = matchingRules2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SYNTAX_OID.get(),
           d1.getSyntaxOID(), d2.getSyntaxOID(), numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE.get(), identifier,
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAX.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the matching rule definitions contained in the provided
   * schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the matching rules.  It
   *                 must not be {@code null}.
   *
   * @return  A map of the matching rule definitions contained in the provided
   *          schema.
   */
  @NotNull()
  private Map<OID,MatchingRuleDefinition> getMatchingRuleMap(
               @NotNull final Schema schema)
  {
    final Map<OID,MatchingRuleDefinition> matchingRules = new TreeMap<>();
    for (final MatchingRuleDefinition d : schema.getMatchingRules())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        matchingRules.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return matchingRules;
  }



  /**
   * Compares the attribute type definitions contained in the provided schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareAttributeTypes(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the attribute type definitions from each of the schemas.
    final Map<OID,AttributeTypeDefinition> attributeTypes1 =
         getAttributeTypeMap(firstServerSchema);
    final Map<OID,AttributeTypeDefinition> attributeTypes2 =
         getAttributeTypeMap(secondServerSchema);


    // Identify attribute types that exist in one server but not another.  If
    // any are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,AttributeTypeDefinition>> iterator =
         attributeTypes1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,AttributeTypeDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! attributeTypes2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_ATTRIBUTE_TYPE.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = attributeTypes2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,AttributeTypeDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! attributeTypes1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_ATTRIBUTE_TYPE.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining attribute types should exist in both servers.  Compare them
    // and see if there are any differences between them.
    for (final OID oid : attributeTypes1.keySet())
    {
      final AttributeTypeDefinition d1 = attributeTypes1.get(oid);
      final AttributeTypeDefinition d2 = attributeTypes2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SUPERIOR_TYPE.get(),
           d1.getSuperiorType(), d2.getSuperiorType(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SYNTAX_OID.get(),
           d1.getSyntaxOID(), d2.getSyntaxOID(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_EQUALITY_MR.get(),
           d1.getEqualityMatchingRule(), d2.getEqualityMatchingRule(),
           numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_ORDERING_MR.get(),
           d1.getOrderingMatchingRule(), d2.getOrderingMatchingRule(),
           numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SUBSTRING_MR.get(),
           d1.getSubstringMatchingRule(), d2.getSubstringMatchingRule(),
           numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_SINGLE_VALUE.get(),
           d1.isSingleValued(), d2.isSingleValued(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_USAGE.get(),
           d1.getUsage().getName(), d2.getUsage().getName(),
           numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_NO_USER_MOD.get(),
           d1.isNoUserModification(), d2.isNoUserModification(),
           numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_COLLECTIVE.get(),
           d1.isCollective(), d2.isCollective(), numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_TYPE.get(), identifier,
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_ATTRIBUTE_SYNTAX.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the attribute type definitions contained in the provided
   * schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the attribute types.  It
   *                 must not be {@code null}.
   *
   * @return  A map of the attribute type definitions contained in the provided
   *          schema.
   */
  @NotNull()
  private Map<OID,AttributeTypeDefinition> getAttributeTypeMap(
               @NotNull final Schema schema)
  {
    final Map<OID,AttributeTypeDefinition> attributeTypes = new TreeMap<>();
    for (final AttributeTypeDefinition d : schema.getAttributeTypes())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        attributeTypes.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return attributeTypes;
  }



  /**
   * Compares the object class definitions contained in the provided schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareObjectClasses(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the object class definitions from each of the schemas.
    final Map<OID,ObjectClassDefinition> objectClasses1 =
         getObjectClassMap(firstServerSchema);
    final Map<OID,ObjectClassDefinition> objectClasses2 =
         getObjectClassMap(secondServerSchema);


    // Identify object classes that exist in one server but not another.  If
    // any are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,ObjectClassDefinition>> iterator =
         objectClasses1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,ObjectClassDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! objectClasses2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_OBJECT_CLASS.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = objectClasses2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,ObjectClassDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! objectClasses1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_OBJECT_CLASS.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining object classes should exist in both servers.  Compare them
    // and see if there are any differences between them.
    for (final OID oid : objectClasses1.keySet())
    {
      final ObjectClassDefinition d1 = objectClasses1.get(oid);
      final ObjectClassDefinition d2 = objectClasses2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SUPERIOR_TYPE.get(),
           d1.getSuperiorClasses(), d2.getSuperiorClasses(), numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_REQUIRED_ATTRIBUTE.get(),
           d1.getRequiredAttributes(), d2.getRequiredAttributes(),
           numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_OPTIONAL_ATTRIBUTE.get(),
           d1.getOptionalAttributes(), d2.getOptionalAttributes(),
           numDifferences);

      final String oc1Type = (d1.getObjectClassType() == null)
           ? null
           : d1.getObjectClassType().getName();
      final String oc2Type = (d2.getObjectClassType() == null)
           ? null
           : d2.getObjectClassType().getName();
      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_OBJECT_CLASS_TYPE.get(),
           oc1Type, oc2Type, numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(), identifier,
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_OBJECT_CLASS.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the object class definitions contained in the provided
   * schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the object classes.  It
   *                 must not be {@code null}.
   *
   * @return  A map of the object class definitions contained in the provided
   *          schema.
   */
  @NotNull()
  private Map<OID,ObjectClassDefinition> getObjectClassMap(
               @NotNull final Schema schema)
  {
    final Map<OID,ObjectClassDefinition> objectClasses = new TreeMap<>();
    for (final ObjectClassDefinition d : schema.getObjectClasses())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        objectClasses.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return objectClasses;
  }



  /**
   * Compares the DIT content rule definitions contained in the provided
   * schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareDITContentRules(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the DIT content rule definitions from each of the schemas.
    final Map<OID,DITContentRuleDefinition> ditContentRules1 =
         getDITContentRuleMap(firstServerSchema);
    final Map<OID,DITContentRuleDefinition> ditContentRules2 =
         getDITContentRuleMap(secondServerSchema);


    // Identify DIT content rules that exist in one server but not another.  If
    // any are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,DITContentRuleDefinition>> iterator =
         ditContentRules1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,DITContentRuleDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! ditContentRules2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_DIT_CONTENT_RULE.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = ditContentRules2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,DITContentRuleDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! ditContentRules1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_DIT_CONTENT_RULE.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining DIT content rules should exist in both servers.  Compare
    // them and see if there are any differences between them.
    for (final OID oid : ditContentRules1.keySet())
    {
      final DITContentRuleDefinition d1 = ditContentRules1.get(oid);
      final DITContentRuleDefinition d2 = ditContentRules2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_REQUIRED_ATTRIBUTE.get(),
           d1.getRequiredAttributes(), d2.getRequiredAttributes(),
           numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_OPTIONAL_ATTRIBUTE.get(),
           d1.getOptionalAttributes(), d2.getOptionalAttributes(),
           numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_PROHIBITED_ATTRIBUTE.get(),
           d1.getProhibitedAttributes(), d2.getProhibitedAttributes(),
           numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_AUXILIARY_CLASS.get(),
           d1.getAuxiliaryClasses(), d2.getAuxiliaryClasses(), numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(),
             identifier,
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_CONTENT_RULE.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the DIT content rule definitions contained in the
   * provided schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the DIT content rules.
   *                 It must not be {@code null}.
   *
   * @return  A map of the DIT content rule definitions contained in the
   *          provided schema.
   */
  @NotNull()
  private Map<OID,DITContentRuleDefinition> getDITContentRuleMap(
               @NotNull final Schema schema)
  {
    final Map<OID,DITContentRuleDefinition> ditContentRules = new TreeMap<>();
    for (final DITContentRuleDefinition d : schema.getDITContentRules())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        ditContentRules.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return ditContentRules;
  }



  /**
   * Compares the DIT structure rule definitions contained in the provided
   * schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareDITStructureRules(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the DIT structure rule definitions from each of the schemas.
    final Map<Integer,DITStructureRuleDefinition> ditStructureRules1 =
         getDITStructureRuleMap(firstServerSchema);
    final Map<Integer,DITStructureRuleDefinition> ditStructureRules2 =
         getDITStructureRuleMap(secondServerSchema);


    // Identify DIT structure rules that exist in one server but not another.
    // If any are found, then report them and remove them from the set.
    Iterator<Map.Entry<Integer,DITStructureRuleDefinition>> iterator =
         ditStructureRules1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<Integer,DITStructureRuleDefinition> e = iterator.next();
      final Integer id = e.getKey();
      if (! ditStructureRules2.containsKey(id))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_DIT_STRUCTURE_RULE.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = ditStructureRules2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<Integer,DITStructureRuleDefinition> e = iterator.next();
      final Integer oid = e.getKey();
      if (! ditStructureRules1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_DIT_STRUCTURE_RULE.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining DIT structure rules should exist in both servers.  Compare
    // them and see if there are any differences between them.
    for (final Integer id : ditStructureRules1.keySet())
    {
      final DITStructureRuleDefinition d1 = ditStructureRules1.get(id);
      final DITStructureRuleDefinition d2 = ditStructureRules2.get(id);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           id.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           identifier, INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_NAME_FORM.get(),
           d1.getNameFormID(), d2.getNameFormID(), numDifferences);

      final String[] superiorRuleIDs1 =
           intArrayToStringArray(d1.getSuperiorRuleIDs());
      final String[] superiorRuleIDs2 =
           intArrayToStringArray(d2.getSuperiorRuleIDs());
      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_SUPERIOR_RULE_ID.get(),
           superiorRuleIDs1, superiorRuleIDs2, numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           identifier, INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           identifier, INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
           d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_DIT_STRUCTURE_RULE.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the DIT structure rule definitions contained in the
   * provided schema, indexed by rule ID.
   *
   * @param  schema  The schema from which to retrieve the DIT structure rules.
   *                 It must not be {@code null}.
   *
   * @return  A map of the DIT structure rule definitions contained in the
   *          provided schema.
   */
  @NotNull()
  private Map<Integer,DITStructureRuleDefinition> getDITStructureRuleMap(
               @NotNull final Schema schema)
  {
    final Map<Integer,DITStructureRuleDefinition> ditStructureRules =
         new TreeMap<>();
    for (final DITStructureRuleDefinition d : schema.getDITStructureRules())
    {
      if (includeBasedOnNameAndExtensions(StaticUtils.NO_STRINGS,
           d.getExtensions()))
      {
        ditStructureRules.put(d.getRuleID(), d);
      }
    }

    return ditStructureRules;
  }



  /**
   * Converts the provided integer array to a string array in which each element
   * is the string representation of the corresponding element in the provided
   * integer array.
   *
   * @param  intArray  The integer array to convert to a string array.  It must
   *                   not be {@code null}, but may be empty.
   *
   * @return  A string array in which each element is the string representation
   *          of the corresponding element in the provided integer array.
   */
  @NotNull()
  private static String[] intArrayToStringArray(@NotNull final int[] intArray)
  {
    final String[] stringArray = new String[intArray.length];
    for (int i=0; i < intArray.length; i++)
    {
      stringArray[i] = String.valueOf(intArray[i]);
    }

    return stringArray;
  }



  /**
   * Compares the name form definitions contained in the provided schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareNameForms(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the name form definitions from each of the schemas.
    final Map<OID,NameFormDefinition> nameForms1 =
         getNameFormMap(firstServerSchema);
    final Map<OID,NameFormDefinition> nameForms2 =
         getNameFormMap(secondServerSchema);


    // Identify name forms that exist in one server but not another.  If
    // any are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,NameFormDefinition>> iterator =
         nameForms1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,NameFormDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! nameForms2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_NAME_FORM.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = nameForms2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,NameFormDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! nameForms1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_NAME_FORM.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining name forms should exist in both servers.  Compare them and
    // see if there are any differences between them.
    for (final OID oid : nameForms1.keySet())
    {
      final NameFormDefinition d1 = nameForms1.get(oid);
      final NameFormDefinition d2 = nameForms2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_STRUCTURAL_CLASS.get(),
           d1.getStructuralClass(), d2.getStructuralClass(), numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_REQUIRED_ATTRIBUTE.get(),
           d1.getRequiredAttributes(), d2.getRequiredAttributes(),
           numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_OPTIONAL_ATTRIBUTE.get(),
           d1.getOptionalAttributes(), d2.getOptionalAttributes(),
           numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
        compareStringValues(
             INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(), identifier,
             INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
             d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_NAME_FORM.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the name form definitions contained in the provided
   * schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the name forms.  It must
   *                 not be {@code null}.
   *
   * @return  A map of the name form definitions contained in the provided
   *          schema.
   */
  @NotNull()
  private Map<OID,NameFormDefinition> getNameFormMap(
               @NotNull final Schema schema)
  {
    final Map<OID,NameFormDefinition> nameForms = new TreeMap<>();
    for (final NameFormDefinition d : schema.getNameForms())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        nameForms.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return nameForms;
  }



  /**
   * Compares the matching rule use definitions contained in the provided
   * schemas.
   *
   * @param  firstServerSchema   The schema retrieved from the first server.  It
   *                             must not be {@code null}.
   * @param  secondServerSchema  The schema retrieved from the second server.
   *                             It must not be {@code null}.
   * @param  numDifferences      A counter used to keep track of the number of
   *                             differences found between the schemas.  It must
   *                             not be {@code null}.
   */
  private void compareMatchingRuleUses(
                    @NotNull final Schema firstServerSchema,
                    @NotNull final Schema secondServerSchema,
                    @NotNull final AtomicInteger numDifferences)
  {
    // Get the matching rule use definitions from each of the schemas.
    final Map<OID,MatchingRuleUseDefinition> matchingRuleUses1 =
         getMatchingRuleUseMap(firstServerSchema);
    final Map<OID,MatchingRuleUseDefinition> matchingRuleUses2 =
         getMatchingRuleUseMap(secondServerSchema);


    // Identify matching rule uses that exist in one server but not another.  If
    // any are found, then report them and remove them from the set.
    Iterator<Map.Entry<OID,MatchingRuleUseDefinition>> iterator =
         matchingRuleUses1.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,MatchingRuleUseDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! matchingRuleUses2.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_MATCHING_RULE_USE.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }

    iterator = matchingRuleUses2.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<OID,MatchingRuleUseDefinition> e = iterator.next();
      final OID oid = e.getKey();
      if (! matchingRuleUses1.containsKey(oid))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_MATCHING_RULE_USE.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences,
             e.getValue().toString());
        iterator.remove();
      }
    }


    // Any remaining matching rule uses should exist in both servers.  Compare
    // them and see if there are any differences between them.
    for (final OID oid : matchingRuleUses1.keySet())
    {
      final MatchingRuleUseDefinition d1 = matchingRuleUses1.get(oid);
      final MatchingRuleUseDefinition d2 = matchingRuleUses2.get(oid);

      final String identifier = compareNames(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get(),
           oid.toString(), d1.getNames(), d2.getNames(), numDifferences);

      compareStringArrayValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_APPLICABLE_ATTRIBUTE.get(),
           d1.getApplicableAttributeTypes(), d2.getApplicableAttributeTypes(),
           numDifferences);

      compareBooleanValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get(), identifier,
           INFO_COMPARE_SCHEMA_BOOLEAN_FIELD_NAME_OBSOLETE.get(),
           d1.isObsolete(), d2.isObsolete(), numDifferences);

      if (! ignoreDescriptions)
      {
      compareStringValues(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get(), identifier,
           INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_DESCRIPTION.get(),
           d1.getDescription(), d2.getDescription(), numDifferences);
      }

      compareExtensions(
           INFO_COMPARE_SCHEMA_ELEMENT_TYPE_MATCHING_RULE_USE.get(),
           identifier, d1.getExtensions(), d2.getExtensions(),
           numDifferences);
    }
  }



  /**
   * Retrieves a map of the matching rule use definitions contained in the
   * provided schema, indexed by OID.
   *
   * @param  schema  The schema from which to retrieve the matching rule uses.
   *                 It must not be {@code null}.
   *
   * @return  A map of the matching rule use definitions contained in the
   *          provided schema.
   */
  @NotNull()
  private Map<OID,MatchingRuleUseDefinition> getMatchingRuleUseMap(
               @NotNull final Schema schema)
  {
    final Map<OID,MatchingRuleUseDefinition> matchingRuleUses = new TreeMap<>();
    for (final MatchingRuleUseDefinition d : schema.getMatchingRuleUses())
    {
      if (includeBasedOnNameAndExtensions(d.getNames(), d.getExtensions()))
      {
        matchingRuleUses.put(new OID(StaticUtils.toLowerCase(d.getOID())), d);
      }
    }

    return matchingRuleUses;
  }



  /**
   * Indicates whether to include a schema element with the given name and set
   * of extensions.
   *
   * @param  names       The set of names for the schema element.  It must not
   *                     be {@code null}, but may be empty.
   * @param  extensions  The set of extensions for the schema element.  It must
   *                     not be {@code null}, but may be empty.
   *
   * @return  {@code true} if an element with the given names and set of
   *          extensions should be included, or {@code false} if not.
   */
  private boolean includeBasedOnNameAndExtensions(
               @NotNull final String[] names,
               @NotNull final Map<String,String[]> extensions)
  {
    if (includeOrExcludeBasedOnName && (names.length > 0))
    {
      boolean includeFound = false;
      for (final String name : names)
      {
        final String lowerName = StaticUtils.toLowerCase(name);
        for (final String excludePrefix : excludeNamePrefixes)
        {
          if (lowerName.startsWith(excludePrefix))
          {
            return false;
          }
        }

        if (! includeNamePrefixes.isEmpty())
        {
          for (final String includePrefix : includeNamePrefixes)
          {
            if (lowerName.startsWith(includePrefix))
            {
              includeFound = true;
              break;
            }
          }
        }
      }

      if ((! includeNamePrefixes.isEmpty()) && (! includeFound))
      {
        return false;
      }
    }


    if (includeOrExcludeBasedOnExtensions && (! extensions.isEmpty()))
    {
      boolean includeFound = false;
      for (final Map.Entry<String,String[]> e : extensions.entrySet())
      {
        final String lowerName = StaticUtils.toLowerCase(e.getKey());
        final String[] values = e.getValue();
        final String[] lowerValues = new String[values.length];
        for (int i=0; i < values.length; i++)
        {
          lowerValues[i] = StaticUtils.toLowerCase(values[i]);
        }

        final List<String> excludeValues =
             excludeExtensionValues.get(lowerName);
        if (excludeValues != null)
        {
          for (final String lowerValue : lowerValues)
          {
            if (excludeValues.contains(lowerValue))
            {
              return false;
            }
          }
        }

        final List<String> includeValues =
             includeExtensionValues.get(lowerName);
        if (includeValues != null)
        {
          for (final String lowerValue : lowerValues)
          {
            if (includeValues.contains(lowerValue))
            {
              includeFound = true;
              break;
            }
          }
        }
      }

      if ((! includeExtensionValues.isEmpty()) && (! includeFound))
      {
        return false;
      }
    }


    return true;
  }



  /**
   * Reports a difference between schema elements.
   *
   * @param  message            The message to display with information about
   *                            the difference.  It must not be {@code null}.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   * @param  additionalStrings  A set of additional strings that should also be
   *                            displayed, in addition to the provided message.
   *                            Each additional string will be presented on its
   *                            own line without any wrapping.  It must not be
   *                            {@code null}, but may be empty.
   */
  private void reportDifference(@NotNull final String message,
                                @NotNull final AtomicInteger numDifferences,
                                @NotNull final String... additionalStrings)
  {
    wrapErr(0, WRAP_COLUMN, message);
    for (final String additionalString : additionalStrings)
    {
      err(additionalString);
    }
    err();
    numDifferences.incrementAndGet();
  }



  /**
   * Identifies differences between string values for two schema elements.
   *
   * @param  elementTypeName    A name for the type of schema element being
   *                            compared.  It must not be {@code null}.
   * @param  elementIdentifier  An identifier (e.g., the name or OID) for the
   *                            schema element for which to make the
   *                            determination.  It must not be {@code null}.
   * @param  stringDescriptor   A descriptor for the string values being
   *                            compared.
   * @param  string1            The string value from the first schema element.
   *                            It may be {@code null} if the element does not
   *                            contain a value for the associated field.
   * @param  string2            The string value from the first second element.
   *                            It may be {@code null} if the element does not
   *                            contain a value for the associated field.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   */
  private void compareStringValues(@NotNull final String elementTypeName,
                                   @NotNull final String elementIdentifier,
                                   @NotNull final String stringDescriptor,
                                   @Nullable final String string1,
                                   @Nullable final String string2,
                                   @NotNull final AtomicInteger numDifferences)
  {
    if (string1 == null)
    {
      if (string2 != null)
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_STRING_MISSING_FROM_SERVER.get(
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  elementTypeName, elementIdentifier, stringDescriptor,
                  string2, INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences);
      }
    }
    else if (string2 == null)
    {
      reportDifference(
           WARN_COMPARE_SCHEMA_STRING_MISSING_FROM_SERVER.get(
                INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                elementTypeName, elementIdentifier, stringDescriptor,
                string1, INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
           numDifferences);
    }
    else if (! string1.equalsIgnoreCase(string2))
    {
      reportDifference(
           WARN_COMPARE_SCHEMA_STRING_DIFFERENT_BETWEEN_SERVERS.get(
                elementTypeName, elementIdentifier, stringDescriptor, string1,
                string2),
           numDifferences);
    }
  }



  /**
   * Identifies differences between the sets of string arrays for two schema
   * elements.
   *
   * @param  elementTypeName    A name for the type of schema element being
   *                            compared.  It must not be {@code null}.
   * @param  elementIdentifier  An identifier (e.g., the name or OID) for the
   *                            schema element for which to make the
   *                            determination.  It must not be {@code null}.
   * @param  stringDescriptor   A descriptor for the string values being
   *                            compared.
   * @param  array1             The array of values for the target field from
   *                            the element in the first schema.  It must not be
   *                            {@code null}, but may be empty.
   * @param  array2             The array of values for the target field from
   *                            the element in the second schema.  It must not
   *                            be {@code null}, but may be empty.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   */
  private void compareStringArrayValues(
                    @NotNull final String elementTypeName,
                    @NotNull final String elementIdentifier,
                    @NotNull final String stringDescriptor,
                    @NotNull final String[] array1,
                    @NotNull final String[] array2,
                    @NotNull final AtomicInteger numDifferences)
  {
    if (array1.length == 0)
    {
      switch (array2.length)
      {
        case 0:
          // The element doesn't have any names in either of the servers, so
          // there is no difference.
          break;
        case 1:
          // The element has names in the second server, but not in the first.
          reportDifference(
               WARN_COMPARE_SCHEMA_STRING_ARRAY_SINGLE_IN_ONLY_ONE_SERVER.get(
                    INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                    elementTypeName, elementIdentifier, stringDescriptor,
                    array2[0], INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
               numDifferences);
          break;
        default:
          reportDifference(
               WARN_COMPARE_SCHEMA_STRING_ARRAY_MULTIPLE_IN_ONLY_ONE_SERVER.get(
                    INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                    elementTypeName, elementIdentifier, stringDescriptor,
                    Arrays.toString(array2),
                    INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
               numDifferences);
          break;
      }
    }
    else if (array2.length == 0)
    {
      // The element has names in the first server, but not in the second.
      if (array1.length == 1)
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_STRING_ARRAY_SINGLE_IN_ONLY_ONE_SERVER.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  elementTypeName, elementIdentifier, stringDescriptor,
                  array1[0], INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences);
      }
      else
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_STRING_ARRAY_MULTIPLE_IN_ONLY_ONE_SERVER.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  elementTypeName, elementIdentifier, stringDescriptor,
                  Arrays.toString(array1),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences);
      }
    }
    else
    {
      // The element has names in both servers.  See if there are any
      // differences between them.
      final Map<String,String> n1 = getNameMap(array1);
      final Map<String,String> n2 = getNameMap(array2);
      for (final Map.Entry<String,String> e : n1.entrySet())
      {
        final String lowerName = e.getKey();
        if (n2.remove(lowerName) == null)
        {
          reportDifference(
               WARN_COMPARE_SCHEMA_STRING_ARRAY_VALUE_MISSING_FROM_SERVER.get(
                    elementTypeName, elementIdentifier, stringDescriptor,
                    INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                    e.getValue(),
                    INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
               numDifferences);
        }
      }

      for (final String nameOnlyInServer2 : n2.values())
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_STRING_ARRAY_VALUE_MISSING_FROM_SERVER.get(
                  elementTypeName, elementIdentifier, stringDescriptor,
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  nameOnlyInServer2,
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences);
      }
    }
  }



  /**
   * Identifies differences between the sets of names for two schema elements.
   *
   * @param  elementTypeName    A name for the type of schema element being
   *                            compared.  It must not be {@code null}.
   * @param  elementIdentifier  An identifier (e.g., the name or OID) for the
   *                            schema element for which to make the
   *                            determination.  It must not be {@code null}.
   * @param  names1             The set of names for the element from the first
   *                            schema.  It must not be {@code null}, but may be
   *                            empty.
   * @param  names2             The set of names for the element from the second
   *                            schema.  It must not be {@code null}, but may be
   *                            empty.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   *
   * @return  The identifier string that should be used to identify the
   *          associated schema element.  If both sets of names are non-empty
   *          and have the same first element, then that name will be used as
   *          the identifier.  Otherwise, the provided identifier will be used.
   */
  @NotNull()
  private String compareNames(@NotNull final String elementTypeName,
                              @NotNull final String elementIdentifier,
                              @NotNull final String[] names1,
                              @NotNull final String[] names2,
                              @NotNull final AtomicInteger numDifferences)
  {
    compareStringArrayValues(elementTypeName, elementIdentifier,
         INFO_COMPARE_SCHEMA_STRING_DESCRIPTOR_NAME.get(), names1, names2,
         numDifferences);


    // Identify the best identifier to use for the schema element going forward.
    if ((names1.length > 0) && (names2.length > 0) &&
         (names1[0].equalsIgnoreCase(names2[0])))
    {
      return names1[0];
    }
    else
    {
      return elementIdentifier;
    }
  }



  /**
   * Identifies difference between boolean values for two schema elements.
   *
   * @param  elementTypeName    A name for the type of schema element being
   *                            compared.  It must not be {@code null}.
   * @param  elementIdentifier  An identifier (e.g., the name or OID) for the
   *                            schema element for which to make the
   *                            determination.  It must not be {@code null}.
   * @param  booleanFieldName   The name of the Boolean field being compared.
   * @param  value1             The Boolean value from the first schema element.
   * @param  value2             The Boolean value from the second schema
   *                            element.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   */
  private void compareBooleanValues(@NotNull final String elementTypeName,
                                    @NotNull final String elementIdentifier,
                                    @NotNull final String booleanFieldName,
                                    final boolean value1,
                                    final boolean value2,
                                    @NotNull final AtomicInteger numDifferences)
  {
    if (value1 != value2)
    {
      if (value1)
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_BOOLEAN_DIFFERENCE.get(
                  elementTypeName, elementIdentifier, booleanFieldName,
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences);
      }
      else
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_BOOLEAN_DIFFERENCE.get(
                  elementTypeName, elementIdentifier, booleanFieldName,
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
             numDifferences);
      }
    }
  }



  /**
   * Identifies differences between the sets of extensions for two schema
   * elements.
   *
   * @param  elementTypeName    A name for the type of schema element being
   *                            compared.  It must not be {@code null}.
   * @param  elementIdentifier  An identifier (e.g., the name or OID) for the
   *                            schema element for which to make the
   *                            determination.  It must not be {@code null}.
   * @param  extensions1        The set of extensions for the element from the
   *                            first schema.  It must not be {@code null}, but
   *                            may be empty.
   * @param  extensions2        The set of extensions for the element from the
   *                            second schema.  It must not be {@code null}, but
   *                            may be empty.
   * @param  numDifferences     A counter used to keep track of the number of
   *                            differences found between the schemas.  It must
   *                            not be {@code null}.
   */
  private void compareExtensions(
                    @NotNull final String elementTypeName,
                    @NotNull final String elementIdentifier,
                    @NotNull final Map<String,String[]> extensions1,
                    @NotNull final Map<String,String[]> extensions2,
                    @NotNull final AtomicInteger numDifferences)
  {
    if (ignoreExtensions)
    {
      return;
    }


    // Convert the extensions into a map of sets so that we can alter the
    // contents of both the map and its sets.
    final Map<String,Set<String>> e1 =
         convertToUpdatableExtensionsMap(extensions1);
    final Map<String,Set<String>> e2 =
         convertToUpdatableExtensionsMap(extensions2);


    // Iterate through the extensions and identify differences between them.
    for (final Map.Entry<String,Set<String>> e : e1.entrySet())
    {
      final String extensionName = e.getKey();
      final Set<String> extension1Values = e.getValue();
      final Set<String> extension2Values = e2.remove(extensionName);
      if (extension2Values == null)
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_MISSING_EXTENSION.get(
                  INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get(),
                  elementTypeName, elementIdentifier, extensionName,
                  INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get()),
             numDifferences);
      }
      else if (! extension1Values.equals(extension2Values))
      {
        reportDifference(
             WARN_COMPARE_SCHEMA_EXTENSION_DIFFERENCE.get(
                  elementTypeName, elementIdentifier, extensionName),
             numDifferences);
      }
    }

    for (final String extensionName : e2.keySet())
    {
      reportDifference(
           WARN_COMPARE_SCHEMA_MISSING_EXTENSION.get(
                INFO_COMPARE_SCHEMA_SECOND_SERVER_LABEL.get(),
                elementTypeName, elementIdentifier, extensionName,
                INFO_COMPARE_SCHEMA_FIRST_SERVER_LABEL.get()),
           numDifferences);
    }
  }



  /**
   * Converts the provided extensions map into an updatable map that associates
   * each extension name key with a modifiable set of values rather than an
   * array.  In addition, all strings will be converted to lowercase for more
   * efficient case-insensitive comparison.
   *
   * @param  extensionsMap  The map to be converted.  It must not be
   *                        {@code null}, but may be empty.
   *
   * @return  A modifiable map that contains the information in the provided map
   *          in a form that is better suited for comparing extensions between
   *          two definitions.
   */
  @NotNull()
  private static Map<String,Set<String>> convertToUpdatableExtensionsMap(
               @NotNull final Map<String,String[]> extensionsMap)
  {
    final Map<String,Set<String>> convertedExtensionsMap = new TreeMap<>();
    for (final Map.Entry<String,String[]> e : extensionsMap.entrySet())
    {
      final String lowerExtensionName = StaticUtils.toLowerCase(e.getKey());
      final Set<String> lowerExtensionValues = new TreeSet<>();
      for (final String extensionValue : e.getValue())
      {
        lowerExtensionValues.add(StaticUtils.toLowerCase(extensionValue));
      }

      convertedExtensionsMap.put(lowerExtensionName, lowerExtensionValues);
    }

    return convertedExtensionsMap;
  }



  /**
   * Retrieves a modifiable map containing the provided names.  The key for each
   * entry in the map will be the name in all lowercase, and the value will be
   * the name in the case in which it is provided.
   *
   * @param  names  The names to include in the resulting map.  It must not be
   *                {@code null}.
   *
   * @return  A modifiable map containing the provided names.
   */
  @NotNull()
  private static Map<String,String> getNameMap(@NotNull final String[] names)
  {
    final Map<String,String> m = new TreeMap<>();
    for (final String name : names)
    {
      m.put(StaticUtils.toLowerCase(name), name);
    }

    return m;
  }



  /**
   * Logs the provided message to standard error and sets it as the tool
   * completion message.
   *
   * @param  message  The completion message.  It must not be {@code null}.
   */
  private void logCompletionError(@NotNull final String message)
  {
    completionMessageRef.compareAndSet(null, message);
    wrapErr(0, WRAP_COLUMN, message);
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
         new String[]
         {
           "--firstHostname", "ds1.example.com",
           "--firstPort", "636",
           "--firstUseSSL",
           "--firstBindDN", "cn=Directory Manager",
           "--firstBindPasswordFile", "/path/to/password.txt",
           "--secondHostname", "ds2.example.com",
           "--secondPort", "636",
           "--secondUseSSL",
           "--secondBindDN", "cn=Directory Manager",
           "--secondBindPasswordFile", "/path/to/password.txt"
         },
         INFO_COMPARE_LDAP_SCHEMAS_EXAMPLE.get());

    return examples;
  }
}
