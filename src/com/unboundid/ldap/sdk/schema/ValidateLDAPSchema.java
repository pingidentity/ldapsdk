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
package com.unboundid.ldap.sdk.schema;



import java.io.File;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a command-line tool that may be used to validate
 * definitions read from one or more schema files.  It uses the
 * {@link SchemaValidator} to perform the core of the processing.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ValidateLDAPSchema
       extends CommandLineTool
{
  /**
   * The column at which long lines should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // A reference to the completion message for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // Arguments used by this tool.
  @Nullable private BooleanArgument allowAttributeTypesWithoutSyntax;
  @Nullable private BooleanArgument allowElementsWithoutNames;
  @Nullable private BooleanArgument allowEmptyDescriptions;
  @Nullable private BooleanArgument allowMultipleEntriesPerSchemaFile;
  @Nullable private BooleanArgument allowNonNumericOIDs;
  @Nullable private BooleanArgument allowRedefiningElements;
  @Nullable private BooleanArgument allowSchemaFilesInSubdirectories;
  @Nullable private BooleanArgument allowStructuralObjectClassesWithoutSuperior;
  @Nullable private BooleanArgument
       rejectAttributeTypesWithoutEqualityMatchingRule;
  @Nullable private BooleanArgument rejectObjectClassesWithMultipleSuperiors;
  @Nullable private BooleanArgument useLenientNameValidation;
  @Nullable private BooleanArgument useLenientOIDValidation;
  @Nullable private FileArgument schemaPath;
  @Nullable private StringArgument allowedElementType;
  @Nullable private StringArgument allowUndefinedElementType;
  @Nullable private StringArgument prohibitedElementType;



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this program.
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
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  A result code that indicates whether processing completed
   *          successfully.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final ValidateLDAPSchema tool = new ValidateLDAPSchema(out, err);
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
  public ValidateLDAPSchema(@Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();

    allowAttributeTypesWithoutSyntax = null;
    allowElementsWithoutNames = null;
    allowEmptyDescriptions = null;
    allowMultipleEntriesPerSchemaFile = null;
    allowNonNumericOIDs = null;
    allowRedefiningElements = null;
    allowSchemaFilesInSubdirectories = null;
    allowStructuralObjectClassesWithoutSuperior = null;
    rejectAttributeTypesWithoutEqualityMatchingRule = null;
    rejectObjectClassesWithMultipleSuperiors = null;
    useLenientNameValidation = null;
    useLenientOIDValidation = null;
    schemaPath = null;
    allowedElementType = null;
    allowUndefinedElementType = null;
    prohibitedElementType = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "validate-ldap-schema";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_VALIDATE_SCHEMA_TOOL_DESCRIPTION.get();
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
    return (! SchemaValidator.PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE);
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
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return completionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    final boolean pingIdentityDSAvailable =
         SchemaValidator.PING_IDENTITY_DIRECTORY_SERVER_AVAILABLE;


    final List<File> defaultSchemaPaths = new ArrayList<>(1);
    if (pingIdentityDSAvailable &&
         (SchemaValidator.PING_IDENTITY_DIRECTORY_SERVER_SCHEMA_DIR != null))
    {
      defaultSchemaPaths.add(
           SchemaValidator.PING_IDENTITY_DIRECTORY_SERVER_SCHEMA_DIR);
    }

    schemaPath = new FileArgument(null, "schema-path", true, 0, null,
         INFO_VALIDATE_SCHEMA_ARG_DESC_SCHEMA_PATH.get(), true, true, false,
         false, defaultSchemaPaths);
    schemaPath.addLongIdentifier("schemaPath", true);
    schemaPath.addLongIdentifier("schema-file", true);
    schemaPath.addLongIdentifier("schemaFile", true);
    schemaPath.addLongIdentifier("schema-directory", true);
    schemaPath.addLongIdentifier("schemaDirectory", true);
    schemaPath.addLongIdentifier("schema-dir", true);
    schemaPath.addLongIdentifier("schemaDir", true);
    schemaPath.addLongIdentifier("file", true);
    schemaPath.addLongIdentifier("directory", true);
    schemaPath.addLongIdentifier("path", true);
    schemaPath.setArgumentGroupName(INFO_VALIDATE_SCHEMA_ARG_GROUP_INPUT.get());
    parser.addArgument(schemaPath);


    allowMultipleEntriesPerSchemaFile = new BooleanArgument(null,
         "allow-multiple-entries-per-schema-file", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_MULTIPLE_ENTRIES.get());
    allowMultipleEntriesPerSchemaFile.addLongIdentifier(
         "allowMultipleEntriesPerSchemaFile", true);
    allowMultipleEntriesPerSchemaFile.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_INPUT.get());
    parser.addArgument(allowMultipleEntriesPerSchemaFile);


    allowSchemaFilesInSubdirectories = new BooleanArgument(null,
         "allow-schema-files-in-subdirectories", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_SUB_DIRS.get());
    allowSchemaFilesInSubdirectories.addLongIdentifier(
         "allow-schema-files-in-sub-directories", true);
    allowSchemaFilesInSubdirectories.addLongIdentifier(
         "allowSchemaFilesInSubDirectories", true);
    allowSchemaFilesInSubdirectories.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_INPUT.get());
    parser.addArgument(allowSchemaFilesInSubdirectories);


    allowedElementType = new StringArgument(null, "allowed-element-type", false,
         0, INFO_VALIDATE_SCHEMA_ARG_PLACEHOLDER_ELEMENT_TYPE.get(),
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOWED_ELEMENT_TYPE.get());
    allowedElementType.addLongIdentifier("allowedElementType", true);
    allowedElementType.addLongIdentifier("allowed-schema-element-type", true);
    allowedElementType.addLongIdentifier("allowedSchemaElementType", true);
    allowedElementType.addLongIdentifier("allow-element-type", true);
    allowedElementType.addLongIdentifier("allowElementType", true);
    allowedElementType.addLongIdentifier("allow-schema-element-type", true);
    allowedElementType.addLongIdentifier("allowSchemaElementType", true);
    allowedElementType.addLongIdentifier("allowed-element", true);
    allowedElementType.addLongIdentifier("allowedElement", true);
    allowedElementType.addLongIdentifier("allow-element", true);
    allowedElementType.addLongIdentifier("allowElement", true);
    allowedElementType.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowedElementType);


    prohibitedElementType = new StringArgument(null, "prohibited-element-type",
         false, 0, INFO_VALIDATE_SCHEMA_ARG_PLACEHOLDER_ELEMENT_TYPE.get(),
         INFO_VALIDATE_SCHEMA_ARG_DESC_PROHIBITED_ELEMENT_TYPE.get());
    prohibitedElementType.addLongIdentifier("prohibitedElementType", true);
    prohibitedElementType.addLongIdentifier("prohibited-schema-element-type",
         true);
    prohibitedElementType.addLongIdentifier("prohibitedSchemaElementType",
         true);
    prohibitedElementType.addLongIdentifier("prohibit-element-type", true);
    prohibitedElementType.addLongIdentifier("prohibitElementType", true);
    prohibitedElementType.addLongIdentifier("prohibit-schema-element-type",
         true);
    prohibitedElementType.addLongIdentifier("prohibitSchemaElementType", true);
    prohibitedElementType.addLongIdentifier("prohibited-element", true);
    prohibitedElementType.addLongIdentifier("prohibitedElement", true);
    prohibitedElementType.addLongIdentifier("prohibit-element", true);
    prohibitedElementType.addLongIdentifier("prohibitElement", true);
    prohibitedElementType.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(prohibitedElementType);


    allowRedefiningElements = new BooleanArgument(null,
         "allow-redefining-elements", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_REDEFINING.get());
    allowRedefiningElements.addLongIdentifier(
         "allow-re-defining-elements", true);
    allowRedefiningElements.addLongIdentifier(
         "allowRedefiningElements", true);
    allowRedefiningElements.addLongIdentifier(
         "allow-redefining-schema-elements", true);
    allowRedefiningElements.addLongIdentifier(
         "allow-re-defining-schema-elements", true);
    allowRedefiningElements.addLongIdentifier(
         "allowRedefiningSchemaElements", true);
    allowRedefiningElements.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowRedefiningElements);


    allowUndefinedElementType = new StringArgument(null,
         "allow-undefined-element-type", false, 0,
         INFO_VALIDATE_SCHEMA_ARG_PLACEHOLDER_ELEMENT_TYPE.get(),
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_UNDEFINED.get());
    allowUndefinedElementType.addLongIdentifier("allowUndefinedElementType",
         true);
    allowUndefinedElementType.addLongIdentifier(
         "allow-undefined-schema-element-type", true);
    allowUndefinedElementType.addLongIdentifier(
         "allowUndefinedSchemaElementType", true);
    allowUndefinedElementType.addLongIdentifier(
         "allowed-undefined-element-type", true);
    allowUndefinedElementType.addLongIdentifier("allowedUndefinedElementType",
         true);
    allowUndefinedElementType.addLongIdentifier(
         "allowed-undefined-schema-element-type", true);
    allowUndefinedElementType.addLongIdentifier(
         "allowedUndefinedSchemaElementType", true);
    allowUndefinedElementType.addLongIdentifier("allow-undefined-element",
         true);
    allowUndefinedElementType.addLongIdentifier("allowUndefinedType", true);
    allowUndefinedElementType.addLongIdentifier("allow-undefined-type", true);
    allowUndefinedElementType.addLongIdentifier("allowUndefinedElement", true);
    allowUndefinedElementType.addLongIdentifier("allowed-undefined-element",
         true);
    allowUndefinedElementType.addLongIdentifier("allowedUndefinedType", true);
    allowUndefinedElementType.addLongIdentifier("allowed-undefined-type", true);
    allowUndefinedElementType.addLongIdentifier("allowedUndefinedElement",
         true);
    allowUndefinedElementType.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowUndefinedElementType);


    useLenientOIDValidation = new BooleanArgument(null,
         "use-lenient-oid-validation", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_LENIENT_OID.get());
    useLenientOIDValidation.addLongIdentifier(
         "useLenientOIDValidation", true);
    useLenientOIDValidation.addLongIdentifier(
         "allow-lenient-oid-validation", true);
    useLenientOIDValidation.addLongIdentifier(
         "allowLenientOIDValidation", true);
    useLenientOIDValidation.addLongIdentifier(
         "lenient-oid-validation", true);
    useLenientOIDValidation.addLongIdentifier(
         "lenientOIDValidation", true);
    useLenientOIDValidation.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(useLenientOIDValidation);


    allowNonNumericOIDs = new BooleanArgument(null, "allow-non-numeric-oids",
         1, INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_NON_NUMERIC_OID.get());
    allowNonNumericOIDs.addLongIdentifier("allow-nonnumeric-oids", true);
    allowNonNumericOIDs.addLongIdentifier("allowNonNumericOIDs", true);
    allowNonNumericOIDs.addLongIdentifier("allow-non-numeric-oid", true);
    allowNonNumericOIDs.addLongIdentifier("allow-nonnumeric-oid", true);
    allowNonNumericOIDs.addLongIdentifier("allowNonNumericOID", true);
    allowNonNumericOIDs.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowNonNumericOIDs);


    allowElementsWithoutNames = new BooleanArgument(null,
         "allow-elements-without-names", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_MISSING_NAME.get());
    allowElementsWithoutNames.addLongIdentifier("allowElementsWithoutNames",
         true);
    allowElementsWithoutNames.addLongIdentifier(
         "allow-schema-elements-without-names", true);
    allowElementsWithoutNames.addLongIdentifier(
         "allowSchemaElementsWithoutNames", true);
    allowElementsWithoutNames.addLongIdentifier("allow-elements-missing-names",
         true);
    allowElementsWithoutNames.addLongIdentifier("allowElementsMissingNames",
         true);
    allowElementsWithoutNames.addLongIdentifier(
         "allow-schema-elements-missing-names", true);
    allowElementsWithoutNames.addLongIdentifier(
         "allowSchemaElementsMissingNames", true);
    allowElementsWithoutNames.addLongIdentifier("allow-missing-names",
         true);
    allowElementsWithoutNames.addLongIdentifier("allowEMissingNames",
         true);
    allowElementsWithoutNames.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowElementsWithoutNames);


    useLenientNameValidation = new BooleanArgument(null,
         "use-lenient-name-validation", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_LENIENT_NAMES.get());
    useLenientNameValidation.addLongIdentifier("useLenientNameValidation",
         true);
    useLenientNameValidation.addLongIdentifier("allow-lenient-name-validation",
         true);
    useLenientNameValidation.addLongIdentifier("allowLenientNameValidation",
         true);
    useLenientNameValidation.addLongIdentifier("lenient-name-validation", true);
    useLenientNameValidation.addLongIdentifier("lenientNameValidation", true);
    useLenientNameValidation.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(useLenientNameValidation);


    allowAttributeTypesWithoutSyntax = new BooleanArgument(null,
         "allow-attribute-types-without-syntax", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_AT_WITHOUT_SYNTAX.get());
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allowAttributeTypesWithoutSyntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allow-attribute-type-without-syntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allowAttributeTypeWithoutSyntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allow-attribute-types-missing-Syntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allowAttributeTypesMissingSyntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allow-attribute-type-missing-syntax", true);
    allowAttributeTypesWithoutSyntax.addLongIdentifier(
         "allowAttributeTypeMissingSyntax", true);
    allowAttributeTypesWithoutSyntax.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowAttributeTypesWithoutSyntax);


    rejectAttributeTypesWithoutEqualityMatchingRule = new BooleanArgument(null,
         "reject-attribute-types-without-equality-matching-rule", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_REJECT_AT_WITHOUT_EQ_MR.get());
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "rejectAttributeTypesWithoutEqualityMatchingRule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "reject-attribute-type-without-equality-matching-rule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "rejectAttributeTypeWithoutEqualityMatchingRule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "reject-attribute-types-missing-equality-matching-rule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "rejectAttributeTypesMissingEqualityMatchingRule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "reject-attribute-type-missing-equality-matching-rule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.addLongIdentifier(
         "rejectAttributeTypeMissingEqualityMatchingRule", true);
    rejectAttributeTypesWithoutEqualityMatchingRule.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(rejectAttributeTypesWithoutEqualityMatchingRule);


    allowStructuralObjectClassesWithoutSuperior = new BooleanArgument(null,
         "allow-structural-object-classes-without-superior", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_MISSING_MISSING_OC_SUP.get());
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-structural-objectclasses-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowStructuralObjectClassesWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-structural-object-class-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-structural-objectclass-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowStructuralObjectClassWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-structural-classes-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowStructuralClassesWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-structural-class-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowStructuralClassWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-object-classes-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-objectclasses-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowObjectClassesWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-object-class-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allow-objectclass-without-superior", true);
    allowStructuralObjectClassesWithoutSuperior.addLongIdentifier(
         "allowObjectClassWithoutSuperior", true);
    allowStructuralObjectClassesWithoutSuperior.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowStructuralObjectClassesWithoutSuperior);


    rejectObjectClassesWithMultipleSuperiors = new BooleanArgument(null,
         "reject-object-classes-with-multiple-superiors", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_REJECT_MULTIPLE_OC_SUP.get());
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-objectclasses-with-multiple-superiors", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "rejectObjectClassesWithMultipleSuperiors", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-object-class-with-multiple-superiors", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-objectclass-with-multiple-superiors", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "rejectObjectClassWithMultipleSuperiors", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-object-classes-with-multiple-superior-classes", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-objectclasses-with-multiple-superior-classes", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "rejectObjectClassesWithMultipleSuperiorClasses", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-object-class-with-multiple-superior-classes", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "reject-objectclass-with-multiple-superior-classes", true);
    rejectObjectClassesWithMultipleSuperiors.addLongIdentifier(
         "rejectObjectClassWithMultipleSuperiorClasses", true);
    rejectObjectClassesWithMultipleSuperiors.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    if (pingIdentityDSAvailable)
    {
      rejectObjectClassesWithMultipleSuperiors.setHidden(true);
    }
    parser.addArgument(rejectObjectClassesWithMultipleSuperiors);


    allowEmptyDescriptions = new BooleanArgument(null,
         "allow-empty-descriptions", 1,
         INFO_VALIDATE_SCHEMA_ARG_DESC_ALLOW_EMPTY_DESC.get());
    allowEmptyDescriptions.addLongIdentifier("allowEmptyDescriptions", true);
    allowEmptyDescriptions.addLongIdentifier("allow-empty-description", true);
    allowEmptyDescriptions.addLongIdentifier("allowEmptyDescription", true);
    allowEmptyDescriptions.addLongIdentifier("allow-empty-desc", true);
    allowEmptyDescriptions.addLongIdentifier("allowEmptyDESC", true);
    allowEmptyDescriptions.setArgumentGroupName(
         INFO_VALIDATE_SCHEMA_ARG_GROUP_VALIDATION.get());
    parser.addArgument(allowEmptyDescriptions);


    // The allowed and prohibited schema element type arguments cannot be used
    // together.
    parser.addExclusiveArgumentSet(allowedElementType, prohibitedElementType);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If the allowed element type argument is present, then validate its
    // values.
    if (allowedElementType.isPresent())
    {
      for (final String value : allowedElementType.getValues())
      {
        if (SchemaElementType.forName(value) == null)
        {
          final String message = ERR_VALIDATE_SCHEMA_NO_SUCH_ELEMENT_TYPE.get(
               value, allowedElementType.getIdentifierString());
          completionMessage.set(message);
          throw new ArgumentException(message);
        }
      }
    }


    // If the prohibited element type argument is present, then validate its
    // values, and make sure that not all element types are prohibited.
    if (prohibitedElementType.isPresent())
    {
      final Set<SchemaElementType> allowedTypes =
           EnumSet.allOf(SchemaElementType.class);

      for (final String value : prohibitedElementType.getValues())
      {
        final SchemaElementType type = SchemaElementType.forName(value);
        if (type == null)
        {
          final String message = ERR_VALIDATE_SCHEMA_NO_SUCH_ELEMENT_TYPE.get(
               value, prohibitedElementType.getIdentifierString());
          completionMessage.set(message);
          throw new ArgumentException(message);
        }
        else
        {
          allowedTypes.remove(type);
        }
      }

      if (allowedTypes.isEmpty())
      {
        final String message =
             ERR_VALIDATE_SCHEMA_ALL_ELEMENT_TYPES_PROHIBITED.get(
                  prohibitedElementType.getIdentifierString());
        completionMessage.set(message);
        throw new ArgumentException(message);
      }
    }


    if (allowUndefinedElementType.isPresent())
    {
      for (final String value : allowUndefinedElementType.getValues())
      {
        if (SchemaElementType.forName(value) == null)
        {
          final String message = ERR_VALIDATE_SCHEMA_NO_SUCH_ELEMENT_TYPE.get(
               value, allowUndefinedElementType.getIdentifierString());
          completionMessage.set(message);
          throw new ArgumentException(message);
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Create the schema validator instance.
    final SchemaValidator schemaValidator = new SchemaValidator();

    schemaValidator.setEnsureSchemaEntryIsValid(true);
    schemaValidator.setAllowInvalidObjectClassInheritance(false);
    schemaValidator.setAllowCollectiveAttributes(true);
    schemaValidator.setAllowObsoleteElements(true);

    schemaValidator.setAllowMultipleEntriesPerFile(
         allowMultipleEntriesPerSchemaFile.isPresent());
    schemaValidator.setAllowSchemaFilesInSubDirectories(
         allowSchemaFilesInSubdirectories.isPresent());
    schemaValidator.setAllowRedefiningElements(
         allowRedefiningElements.isPresent());
    schemaValidator.setAllowElementsWithoutNames(
         allowElementsWithoutNames.isPresent());
    schemaValidator.setOIDValidation(
         allowNonNumericOIDs.isPresent(),
         allowNonNumericOIDs.isPresent(),
         (! useLenientOIDValidation.isPresent()));
    schemaValidator.setAllowNamesWithInitialDigit(
         useLenientNameValidation.isPresent());
    schemaValidator.setAllowNamesWithInitialHyphen(
         useLenientNameValidation.isPresent());
    schemaValidator.setAllowNamesWithUnderscore(
         useLenientNameValidation.isPresent());
    schemaValidator.setAllowEmptyDescription(
         allowEmptyDescriptions.isPresent());
    schemaValidator.setAllowAttributeTypesWithoutSyntax(
         allowAttributeTypesWithoutSyntax.isPresent());
    schemaValidator.setAllowAttributeTypesWithoutEqualityMatchingRule(
         ! rejectAttributeTypesWithoutEqualityMatchingRule.isPresent());
    schemaValidator.setAllowStructuralObjectClassWithoutSuperior(
         allowStructuralObjectClassesWithoutSuperior.isPresent());
    schemaValidator.setAllowMultipleSuperiorObjectClasses(
         ! rejectObjectClassesWithMultipleSuperiors.isPresent());

    if (allowedElementType.isPresent())
    {
      final Set<SchemaElementType> allowedTypes =
           EnumSet.noneOf(SchemaElementType.class);
      for (final String value : allowedElementType.getValues())
      {
        allowedTypes.add(SchemaElementType.forName(value));
      }

      schemaValidator.setAllowedSchemaElementTypes(allowedTypes);
    }
    else if (prohibitedElementType.isPresent())
    {
      final Set<SchemaElementType> allowedTypes =
           EnumSet.allOf(SchemaElementType.class);
      for (final String value : prohibitedElementType.getValues())
      {
        allowedTypes.remove(SchemaElementType.forName(value));
      }

      schemaValidator.setAllowedSchemaElementTypes(allowedTypes);
    }

    if (allowUndefinedElementType.isPresent())
    {
      final Set<SchemaElementType> elementTypes =
           EnumSet.noneOf(SchemaElementType.class);
      for (final String value : allowUndefinedElementType.getValues())
      {
        elementTypes.add(SchemaElementType.forName(value));
      }

      schemaValidator.setAllowReferencesToUndefinedElementTypes(elementTypes);
    }


    // Use the schema validator to parse the scheme elements in the provided
    // paths.
    Schema schema = null;
    final List<String> errorMessages = new ArrayList<>();
    for (final File f : schemaPath.getValues())
    {
      schema = schemaValidator.validateSchema(f, schema, errorMessages);
    }


    // If we ended up with an empty set of error messages, then return a success
    // result.
    final int numErrors = errorMessages.size();
    if (numErrors == 0)
    {
        completionMessage.set(INFO_VALIDATE_SCHEMA_NO_ERRORS.get());
        wrapOut(0, WRAP_COLUMN, INFO_VALIDATE_SCHEMA_NO_ERRORS.get());
        return ResultCode.SUCCESS;
    }


    // If we've gotten here, then there were errors.  Display them and get the
    // final string to use as the completion message.
    final String finalMessage;
    if (numErrors == 1)
    {
      wrapErr(0, WRAP_COLUMN, ERR_VALIDATE_SCHEMA_ERROR_FOUND.get());
      finalMessage = ERR_VALIDATE_SCHEMA_ONE_ERROR.get();
    }
    else
    {
      wrapErr(0, WRAP_COLUMN, ERR_VALIDATE_SCHEMA_ERRORS_FOUND.get());
      finalMessage = ERR_VALIDATE_SCHEMA_MULTIPLE_ERRORS.get(numErrors);
    }

    for (final String errorMessage : errorMessages)
    {
      err();

      boolean firstLine = true;
      for (final String line :
           StaticUtils.wrapLine(errorMessage, (WRAP_COLUMN - 2)))
      {
        if (firstLine)
        {
          err("* " + line);
          firstLine = false;
        }
        else
        {
          err("  " + line);
        }
      }
    }

    completionMessage.set(finalMessage);

    err();
    wrapErr(0, WRAP_COLUMN, finalMessage);

    return ResultCode.DECODING_ERROR;
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
           "--schema-path", "/path/to/schema"
         },
         INFO_VALIDATE_SCHEMA_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--schema-path", "/path/to/schema",
           "--allow-multiple-entries-per-schema-file",
           "--allow-schema-files-in-subdirectories",
           "--allow-redefining-elements",
           "--allow-undefined-element-type", "attribute-syntax",
           "--allow-undefined-element-type", "matching-rule",
           "--use-lenient-oid-validation",
           "--allow-non-numeric-oids",
           "--allow-elements-without-names",
           "--use-lenient-name-validation",
           "--allow-attribute-types-without-syntax",
           "--allow-structural-object-classes-without-superior",
           "--allow-empty-descriptions"
         },
         INFO_VALIDATE_SCHEMA_EXAMPLE_2.get());

    return examples;
  }
}
