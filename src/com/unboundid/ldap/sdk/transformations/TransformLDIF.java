/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.ldif.AggregateLDIFReaderChangeRecordTranslator;
import com.unboundid.ldif.AggregateLDIFReaderEntryTranslator;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFReaderChangeRecordTranslator;
import com.unboundid.ldif.LDIFReaderEntryTranslator;
import com.unboundid.ldif.LDIFRecord;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.transformations.TransformationMessages.*;



/**
 * This class provides a command-line tool that can be used to apply a number of
 * transformations to an LDIF file.  The transformations that can be applied
 * include:
 * <UL>
 *   <LI>
 *     It can scramble the values of a specified set of attributes in a manner
 *     that attempts to preserve the syntax and consistently scrambles the same
 *     value to the same representation.
 *   </LI>
 *   <LI>
 *     It can strip a specified set of attributes out of entries.
 *   </LI>
 *   <LI>
 *     It can redact the values of a specified set of attributes, to indicate
 *     that the values are there but providing no information about what their
 *     values are.
 *   </LI>
 *   <LI>
 *     It can replace the values of a specified attribute with a given set of
 *     values.
 *   </LI>
 *   <LI>
 *     It can add an attribute with a given set of values to any entry that does
 *     not contain that attribute.
 *   </LI>
 *   <LI>
 *     It can replace the values of a specified attribute with a value that
 *     contains a sequentially-incrementing counter.
 *   </LI>
 *   <LI>
 *     It can strip entries matching a given base DN, scope, and filter out of
 *     the LDIF file.
 *   </LI>
 *   <LI>
 *     It can perform DN mapping, so that entries that exist below one base DN
 *     are moved below a different base DN.
 *   </LI>
 *   <LI>
 *     It can perform attribute mapping, to replace uses of one attribute name
 *     with another.
 *   </LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TransformLDIF
       extends CommandLineTool
       implements LDIFReaderEntryTranslator
{
  /**
   * The maximum length of any message to write to standard output or standard
   * error.
   */
  private static final int MAX_OUTPUT_LINE_LENGTH =
       StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // The arguments for use by this program.
  @Nullable private BooleanArgument addToExistingValues = null;
  @Nullable private BooleanArgument appendToTargetLDIF = null;
  @Nullable private BooleanArgument compressTarget = null;
  @Nullable private BooleanArgument encryptTarget = null;
  @Nullable private BooleanArgument excludeRecordsWithoutChangeType = null;
  @Nullable private BooleanArgument excludeNonMatchingEntries = null;
  @Nullable private BooleanArgument flattenAddOmittedRDNAttributesToEntry =
       null;
  @Nullable private BooleanArgument flattenAddOmittedRDNAttributesToRDN = null;
  @Nullable private BooleanArgument hideRedactedValueCount = null;
  @Nullable private BooleanArgument processDNs = null;
  @Nullable private BooleanArgument sourceCompressed = null;
  @Nullable private BooleanArgument sourceContainsChangeRecords = null;
  @Nullable private BooleanArgument sourceFromStandardInput = null;
  @Nullable private BooleanArgument targetToStandardOutput = null;
  @Nullable private DNArgument addAttributeBaseDN = null;
  @Nullable private DNArgument excludeEntryBaseDN = null;
  @Nullable private DNArgument flattenBaseDN = null;
  @Nullable private DNArgument moveSubtreeFrom = null;
  @Nullable private DNArgument moveSubtreeTo = null;
  @Nullable private FileArgument encryptionPassphraseFile = null;
  @Nullable private FileArgument schemaPath = null;
  @Nullable private FileArgument sourceLDIF = null;
  @Nullable private FileArgument targetLDIF = null;
  @Nullable private FilterArgument addAttributeFilter = null;
  @Nullable private FilterArgument excludeEntryFilter = null;
  @Nullable private FilterArgument flattenExcludeFilter = null;
  @Nullable private IntegerArgument initialSequentialValue = null;
  @Nullable private IntegerArgument numThreads = null;
  @Nullable private IntegerArgument randomSeed = null;
  @Nullable private IntegerArgument sequentialValueIncrement = null;
  @Nullable private IntegerArgument wrapColumn = null;
  @Nullable private ScopeArgument addAttributeScope = null;
  @Nullable private ScopeArgument excludeEntryScope = null;
  @Nullable private StringArgument addAttributeName = null;
  @Nullable private StringArgument addAttributeValue = null;
  @Nullable private StringArgument excludeAttribute = null;
  @Nullable private StringArgument excludeChangeType  = null;
  @Nullable private StringArgument redactAttribute = null;
  @Nullable private StringArgument renameAttributeFrom = null;
  @Nullable private StringArgument renameAttributeTo = null;
  @Nullable private StringArgument replaceValuesAttribute = null;
  @Nullable private StringArgument replacementValue = null;
  @Nullable private StringArgument scrambleAttribute = null;
  @Nullable private StringArgument scrambleJSONField = null;
  @Nullable private StringArgument sequentialAttribute = null;
  @Nullable private StringArgument textAfterSequentialValue = null;
  @Nullable private StringArgument textBeforeSequentialValue = null;

  // A set of thread-local byte stream buffers that will be used to construct
  // the LDIF representations of records.
  @NotNull private final ThreadLocal<ByteStringBuffer> byteStringBuffers =
       new ThreadLocal<>();



  /**
   * Invokes this tool with the provided set of arguments.
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
   * Invokes this tool with the provided set of arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  A result code indicating whether processing completed
   *          successfully.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final TransformLDIF tool = new TransformLDIF(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided information.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public TransformLDIF(@Nullable final OutputStream out,
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
    return "transform-ldif";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_TRANSFORM_LDIF_TOOL_DESCRIPTION.get();
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
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    // Add arguments pertaining to the source and target LDIF files.
    sourceLDIF = new FileArgument('l', "sourceLDIF", false, 0, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_SOURCE_LDIF.get(), true, true, true,
         false);
    sourceLDIF.addLongIdentifier("inputLDIF", true);
    sourceLDIF.addLongIdentifier("source-ldif", true);
    sourceLDIF.addLongIdentifier("input-ldif", true);
    sourceLDIF.setArgumentGroupName(INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(sourceLDIF);

    sourceFromStandardInput = new BooleanArgument(null,
         "sourceFromStandardInput", 1,
         INFO_TRANSFORM_LDIF_ARG_DESC_SOURCE_STD_IN.get());
    sourceFromStandardInput.addLongIdentifier("source-from-standard-input",
         true);
    sourceFromStandardInput.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(sourceFromStandardInput);
    parser.addRequiredArgumentSet(sourceLDIF, sourceFromStandardInput);
    parser.addExclusiveArgumentSet(sourceLDIF, sourceFromStandardInput);

    targetLDIF = new FileArgument('o', "targetLDIF", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_TARGET_LDIF.get(), false, true, true,
         false);
    targetLDIF.addLongIdentifier("outputLDIF", true);
    targetLDIF.addLongIdentifier("target-ldif", true);
    targetLDIF.addLongIdentifier("output-ldif", true);
    targetLDIF.setArgumentGroupName(INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(targetLDIF);

    targetToStandardOutput = new BooleanArgument(null, "targetToStandardOutput",
         1, INFO_TRANSFORM_LDIF_ARG_DESC_TARGET_STD_OUT.get());
    targetToStandardOutput.addLongIdentifier("target-to-standard-output", true);
    targetToStandardOutput.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(targetToStandardOutput);
    parser.addExclusiveArgumentSet(targetLDIF, targetToStandardOutput);

    sourceContainsChangeRecords = new BooleanArgument(null,
         "sourceContainsChangeRecords",
         INFO_TRANSFORM_LDIF_ARG_DESC_SOURCE_CONTAINS_CHANGE_RECORDS.get());
    sourceContainsChangeRecords.addLongIdentifier(
         "source-contains-change-records", true);
    sourceContainsChangeRecords.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(sourceContainsChangeRecords);

    appendToTargetLDIF = new BooleanArgument(null, "appendToTargetLDIF",
         INFO_TRANSFORM_LDIF_ARG_DESC_APPEND_TO_TARGET.get());
    appendToTargetLDIF.addLongIdentifier("append-to-target-ldif", true);
    appendToTargetLDIF.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(appendToTargetLDIF);
    parser.addExclusiveArgumentSet(targetToStandardOutput, appendToTargetLDIF);

    wrapColumn = new IntegerArgument(null, "wrapColumn", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_WRAP_COLUMN.get(), 5, Integer.MAX_VALUE);
    wrapColumn.addLongIdentifier("wrap-column", true);
    wrapColumn.setArgumentGroupName(INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(wrapColumn);

    sourceCompressed = new BooleanArgument('C', "sourceCompressed",
         INFO_TRANSFORM_LDIF_ARG_DESC_SOURCE_COMPRESSED.get());
    sourceCompressed.addLongIdentifier("inputCompressed", true);
    sourceCompressed.addLongIdentifier("source-compressed", true);
    sourceCompressed.addLongIdentifier("input-compressed", true);
    sourceCompressed.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(sourceCompressed);

    compressTarget = new BooleanArgument('c', "compressTarget",
         INFO_TRANSFORM_LDIF_ARG_DESC_COMPRESS_TARGET.get());
    compressTarget.addLongIdentifier("compressOutput", true);
    compressTarget.addLongIdentifier("compress", true);
    compressTarget.addLongIdentifier("compress-target", true);
    compressTarget.addLongIdentifier("compress-output", true);
    compressTarget.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(compressTarget);

    encryptTarget = new BooleanArgument(null, "encryptTarget",
         INFO_TRANSFORM_LDIF_ARG_DESC_ENCRYPT_TARGET.get());
    encryptTarget.addLongIdentifier("encryptOutput", true);
    encryptTarget.addLongIdentifier("encrypt", true);
    encryptTarget.addLongIdentifier("encrypt-target", true);
    encryptTarget.addLongIdentifier("encrypt-output", true);
    encryptTarget.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(encryptTarget);

    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_ENCRYPTION_PW_FILE.get(), true, true,
         true, false);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    encryptionPassphraseFile.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_LDIF.get());
    parser.addArgument(encryptionPassphraseFile);


    // Add arguments pertaining to attribute scrambling.
    scrambleAttribute = new StringArgument('a', "scrambleAttribute", false, 0,
         INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_SCRAMBLE_ATTR.get());
    scrambleAttribute.addLongIdentifier("attributeName", true);
    scrambleAttribute.addLongIdentifier("scramble-attribute", true);
    scrambleAttribute.addLongIdentifier("attribute-name", true);
    scrambleAttribute.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SCRAMBLE.get());
    parser.addArgument(scrambleAttribute);

    scrambleJSONField = new StringArgument(null, "scrambleJSONField", false, 0,
         INFO_TRANSFORM_LDIF_PLACEHOLDER_FIELD_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_SCRAMBLE_JSON_FIELD.get(
              scrambleAttribute.getIdentifierString()));
    scrambleJSONField.addLongIdentifier("scramble-json-field", true);
    scrambleJSONField.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SCRAMBLE.get());
    parser.addArgument(scrambleJSONField);
    parser.addDependentArgumentSet(scrambleJSONField, scrambleAttribute);

    randomSeed = new IntegerArgument('s', "randomSeed", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_RANDOM_SEED.get());
    randomSeed.addLongIdentifier("random-seed", true);
    randomSeed.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SCRAMBLE.get());
    parser.addArgument(randomSeed);


    // Add arguments pertaining to replacing attribute values with a generated
    // value using a sequential counter.
    sequentialAttribute = new StringArgument('S', "sequentialAttribute",
         false, 0, INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_SEQUENTIAL_ATTR.get(
              sourceContainsChangeRecords.getIdentifierString()));
    sequentialAttribute.addLongIdentifier("sequentialAttributeName", true);
    sequentialAttribute.addLongIdentifier("sequential-attribute", true);
    sequentialAttribute.addLongIdentifier("sequential-attribute-name", true);
    sequentialAttribute.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SEQUENTIAL.get());
    parser.addArgument(sequentialAttribute);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         sequentialAttribute);

    initialSequentialValue = new IntegerArgument('i', "initialSequentialValue",
         false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_INITIAL_SEQUENTIAL_VALUE.get(
              sequentialAttribute.getIdentifierString()));
    initialSequentialValue.addLongIdentifier("initial-sequential-value", true);
    initialSequentialValue.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SEQUENTIAL.get());
    parser.addArgument(initialSequentialValue);
    parser.addDependentArgumentSet(initialSequentialValue, sequentialAttribute);

    sequentialValueIncrement = new IntegerArgument(null,
         "sequentialValueIncrement", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_SEQUENTIAL_INCREMENT.get(
              sequentialAttribute.getIdentifierString()));
    sequentialValueIncrement.addLongIdentifier("sequential-value-increment",
         true);
    sequentialValueIncrement.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SEQUENTIAL.get());
    parser.addArgument(sequentialValueIncrement);
    parser.addDependentArgumentSet(sequentialValueIncrement,
         sequentialAttribute);

    textBeforeSequentialValue = new StringArgument(null,
         "textBeforeSequentialValue", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_SEQUENTIAL_TEXT_BEFORE.get(
              sequentialAttribute.getIdentifierString()));
    textBeforeSequentialValue.addLongIdentifier("text-before-sequential-value",
         true);
    textBeforeSequentialValue.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SEQUENTIAL.get());
    parser.addArgument(textBeforeSequentialValue);
    parser.addDependentArgumentSet(textBeforeSequentialValue,
         sequentialAttribute);

    textAfterSequentialValue = new StringArgument(null,
         "textAfterSequentialValue", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_SEQUENTIAL_TEXT_AFTER.get(
              sequentialAttribute.getIdentifierString()));
    textAfterSequentialValue.addLongIdentifier("text-after-sequential-value",
         true);
    textAfterSequentialValue.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_SEQUENTIAL.get());
    parser.addArgument(textAfterSequentialValue);
    parser.addDependentArgumentSet(textAfterSequentialValue,
         sequentialAttribute);


    // Add arguments pertaining to attribute value replacement.
    replaceValuesAttribute = new StringArgument(null, "replaceValuesAttribute",
         false, 1, INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_REPLACE_VALUES_ATTR.get(
              sourceContainsChangeRecords.getIdentifierString()));
    replaceValuesAttribute.addLongIdentifier("replace-values-attribute", true);
    replaceValuesAttribute.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_REPLACE_VALUES.get());
    parser.addArgument(replaceValuesAttribute);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         replaceValuesAttribute);

    replacementValue = new StringArgument(null, "replacementValue", false, 0,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_REPLACEMENT_VALUE.get(
              replaceValuesAttribute.getIdentifierString()));
    replacementValue.addLongIdentifier("replacement-value", true);
    replacementValue.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_REPLACE_VALUES.get());
    parser.addArgument(replacementValue);
    parser.addDependentArgumentSet(replaceValuesAttribute, replacementValue);
    parser.addDependentArgumentSet(replacementValue, replaceValuesAttribute);


    // Add arguments pertaining to adding missing attributes.
    addAttributeName = new StringArgument(null, "addAttributeName", false, 1,
         INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_ATTR.get(
              "--addAttributeValue",
              sourceContainsChangeRecords.getIdentifierString()));
    addAttributeName.addLongIdentifier("add-attribute-name", true);
    addAttributeName.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addAttributeName);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         addAttributeName);

    addAttributeValue = new StringArgument(null, "addAttributeValue", false, 0,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_VALUE.get(
              addAttributeName.getIdentifierString()));
    addAttributeValue.addLongIdentifier("add-attribute-value", true);
    addAttributeValue.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addAttributeValue);
    parser.addDependentArgumentSet(addAttributeName, addAttributeValue);
    parser.addDependentArgumentSet(addAttributeValue, addAttributeName);

    addToExistingValues = new BooleanArgument(null, "addToExistingValues",
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_MERGE_VALUES.get(
              addAttributeName.getIdentifierString(),
              addAttributeValue.getIdentifierString()));
    addToExistingValues.addLongIdentifier("add-to-existing-values", true);
    addToExistingValues.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addToExistingValues);
    parser.addDependentArgumentSet(addToExistingValues, addAttributeName);

    addAttributeBaseDN = new DNArgument(null, "addAttributeBaseDN", false, 1,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_BASE_DN.get(
              addAttributeName.getIdentifierString()));
    addAttributeBaseDN.addLongIdentifier("add-attribute-base-dn", true);
    addAttributeBaseDN.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addAttributeBaseDN);
    parser.addDependentArgumentSet(addAttributeBaseDN, addAttributeName);

    addAttributeScope = new ScopeArgument(null, "addAttributeScope", false,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_SCOPE.get(
              addAttributeBaseDN.getIdentifierString(),
              addAttributeName.getIdentifierString()));
    addAttributeScope.addLongIdentifier("add-attribute-scope", true);
    addAttributeScope.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addAttributeScope);
    parser.addDependentArgumentSet(addAttributeScope, addAttributeName);

    addAttributeFilter = new FilterArgument(null, "addAttributeFilter", false,
         1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_ADD_FILTER.get(
              addAttributeName.getIdentifierString()));
    addAttributeFilter.addLongIdentifier("add-attribute-filter", true);
    addAttributeFilter.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_ADD_ATTR.get());
    parser.addArgument(addAttributeFilter);
    parser.addDependentArgumentSet(addAttributeFilter, addAttributeName);


    // Add arguments pertaining to renaming attributes.
    renameAttributeFrom = new StringArgument(null, "renameAttributeFrom",
         false, 0, INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_RENAME_FROM.get());
    renameAttributeFrom.addLongIdentifier("rename-attribute-from", true);
    renameAttributeFrom.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_RENAME.get());
    parser.addArgument(renameAttributeFrom);

    renameAttributeTo = new StringArgument(null, "renameAttributeTo",
         false, 0, INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_RENAME_TO.get(
              renameAttributeFrom.getIdentifierString()));
    renameAttributeTo.addLongIdentifier("rename-attribute-to", true);
    renameAttributeTo.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_RENAME.get());
    parser.addArgument(renameAttributeTo);
    parser.addDependentArgumentSet(renameAttributeFrom, renameAttributeTo);
    parser.addDependentArgumentSet(renameAttributeTo, renameAttributeFrom);


    // Add arguments pertaining to flattening subtrees.
    flattenBaseDN = new DNArgument(null, "flattenBaseDN", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_FLATTEN_BASE_DN.get());
    flattenBaseDN.addLongIdentifier("flatten-base-dn", true);
    flattenBaseDN.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_FLATTEN.get());
    parser.addArgument(flattenBaseDN);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         flattenBaseDN);

    flattenAddOmittedRDNAttributesToEntry = new BooleanArgument(null,
         "flattenAddOmittedRDNAttributesToEntry", 1,
         INFO_TRANSFORM_LDIF_ARG_DESC_FLATTEN_ADD_OMITTED_TO_ENTRY.get());
    flattenAddOmittedRDNAttributesToEntry.addLongIdentifier(
         "flatten-add-omitted-rdn-attributes-to-entry", true);
    flattenAddOmittedRDNAttributesToEntry.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_FLATTEN.get());
    parser.addArgument(flattenAddOmittedRDNAttributesToEntry);
    parser.addDependentArgumentSet(flattenAddOmittedRDNAttributesToEntry,
         flattenBaseDN);

    flattenAddOmittedRDNAttributesToRDN = new BooleanArgument(null,
         "flattenAddOmittedRDNAttributesToRDN", 1,
         INFO_TRANSFORM_LDIF_ARG_DESC_FLATTEN_ADD_OMITTED_TO_RDN.get());
    flattenAddOmittedRDNAttributesToRDN.addLongIdentifier(
         "flatten-add-omitted-rdn-attributes-to-rdn", true);
    flattenAddOmittedRDNAttributesToRDN.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_FLATTEN.get());
    parser.addArgument(flattenAddOmittedRDNAttributesToRDN);
    parser.addDependentArgumentSet(flattenAddOmittedRDNAttributesToRDN,
         flattenBaseDN);

    flattenExcludeFilter = new FilterArgument(null, "flattenExcludeFilter",
         false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_FLATTEN_EXCLUDE_FILTER.get());
    flattenExcludeFilter.addLongIdentifier("flatten-exclude-filter", true);
    flattenExcludeFilter.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_FLATTEN.get());
    parser.addArgument(flattenExcludeFilter);
    parser.addDependentArgumentSet(flattenExcludeFilter, flattenBaseDN);


    // Add arguments pertaining to moving subtrees.
    moveSubtreeFrom = new DNArgument(null, "moveSubtreeFrom", false, 0, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_MOVE_SUBTREE_FROM.get());
    moveSubtreeFrom.addLongIdentifier("move-subtree-from", true);
    moveSubtreeFrom.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_MOVE.get());
    parser.addArgument(moveSubtreeFrom);

    moveSubtreeTo = new DNArgument(null, "moveSubtreeTo", false, 0, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_MOVE_SUBTREE_TO.get(
              moveSubtreeFrom.getIdentifierString()));
    moveSubtreeTo.addLongIdentifier("move-subtree-to", true);
    moveSubtreeTo.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_MOVE.get());
    parser.addArgument(moveSubtreeTo);
    parser.addDependentArgumentSet(moveSubtreeFrom, moveSubtreeTo);
    parser.addDependentArgumentSet(moveSubtreeTo, moveSubtreeFrom);


    // Add arguments pertaining to redacting attribute values.
    redactAttribute = new StringArgument(null, "redactAttribute", false, 0,
         INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_REDACT_ATTR.get());
    redactAttribute.addLongIdentifier("redact-attribute", true);
    redactAttribute.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_REDACT.get());
    parser.addArgument(redactAttribute);

    hideRedactedValueCount = new BooleanArgument(null, "hideRedactedValueCount",
         INFO_TRANSFORM_LDIF_ARG_DESC_HIDE_REDACTED_COUNT.get());
    hideRedactedValueCount.addLongIdentifier("hide-redacted-value-count",
         true);
    hideRedactedValueCount.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_REDACT.get());
    parser.addArgument(hideRedactedValueCount);
    parser.addDependentArgumentSet(hideRedactedValueCount, redactAttribute);


    // Add arguments pertaining to excluding attributes and entries.
    excludeAttribute = new StringArgument(null, "excludeAttribute", false, 0,
         INFO_TRANSFORM_LDIF_PLACEHOLDER_ATTR_NAME.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_ATTR.get());
    excludeAttribute.addLongIdentifier("suppressAttribute", true);
    excludeAttribute.addLongIdentifier("exclude-attribute", true);
    excludeAttribute.addLongIdentifier("suppress-attribute", true);
    excludeAttribute.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeAttribute);

    excludeEntryBaseDN = new DNArgument(null, "excludeEntryBaseDN", false, 1,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_ENTRY_BASE_DN.get(
              sourceContainsChangeRecords.getIdentifierString()));
    excludeEntryBaseDN.addLongIdentifier("suppressEntryBaseDN", true);
    excludeEntryBaseDN.addLongIdentifier("exclude-entry-base-dn", true);
    excludeEntryBaseDN.addLongIdentifier("suppress-entry-base-dn", true);
    excludeEntryBaseDN.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeEntryBaseDN);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         excludeEntryBaseDN);

    excludeEntryScope = new ScopeArgument(null, "excludeEntryScope", false,
         null,
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_ENTRY_SCOPE.get(
              sourceContainsChangeRecords.getIdentifierString()));
    excludeEntryScope.addLongIdentifier("suppressEntryScope", true);
    excludeEntryScope.addLongIdentifier("exclude-entry-scope", true);
    excludeEntryScope.addLongIdentifier("suppress-entry-scope", true);
    excludeEntryScope.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeEntryScope);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         excludeEntryScope);

    excludeEntryFilter = new FilterArgument(null, "excludeEntryFilter", false,
         1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_ENTRY_FILTER.get(
              sourceContainsChangeRecords.getIdentifierString()));
    excludeEntryFilter.addLongIdentifier("suppressEntryFilter", true);
    excludeEntryFilter.addLongIdentifier("exclude-entry-filter", true);
    excludeEntryFilter.addLongIdentifier("suppress-entry-filter", true);
    excludeEntryFilter.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeEntryFilter);
    parser.addExclusiveArgumentSet(sourceContainsChangeRecords,
         excludeEntryFilter);

    excludeNonMatchingEntries = new BooleanArgument(null,
         "excludeNonMatchingEntries",
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_NON_MATCHING.get());
    excludeNonMatchingEntries.addLongIdentifier("exclude-non-matching-entries",
         true);
    excludeNonMatchingEntries.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeNonMatchingEntries);
    parser.addDependentArgumentSet(excludeNonMatchingEntries,
         excludeEntryBaseDN, excludeEntryScope, excludeEntryFilter);


    // Add arguments for excluding records based on their change types.
    excludeChangeType = new StringArgument(null, "excludeChangeType",
         false, 0, INFO_TRANSFORM_LDIF_PLACEHOLDER_CHANGE_TYPES.get(),
         INFO_TRANSFORM_LDIF_ARG_DESC_EXCLUDE_CHANGE_TYPE.get(),
         StaticUtils.setOf("add", "delete", "modify", "moddn"));
    excludeChangeType.addLongIdentifier("exclude-change-type", true);
    excludeChangeType.addLongIdentifier("exclude-changetype", true);
    excludeChangeType.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeChangeType);


    // Add arguments for excluding records that don't have a change type.
    excludeRecordsWithoutChangeType = new BooleanArgument(null,
         "excludeRecordsWithoutChangeType", 1,
         INFO_TRANSFORM_LDIF_EXCLUDE_WITHOUT_CHANGETYPE.get());
    excludeRecordsWithoutChangeType.addLongIdentifier(
         "exclude-records-without-change-type", true);
    excludeRecordsWithoutChangeType.addLongIdentifier(
         "exclude-records-without-changetype", true);
    excludeRecordsWithoutChangeType.setArgumentGroupName(
         INFO_TRANSFORM_LDIF_ARG_GROUP_EXCLUDE.get());
    parser.addArgument(excludeRecordsWithoutChangeType);


    // Add the remaining arguments.
    schemaPath = new FileArgument(null, "schemaPath", false, 0, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_SCHEMA_PATH.get(),
         true, true, false, false);
    schemaPath.addLongIdentifier("schemaFile", true);
    schemaPath.addLongIdentifier("schemaDirectory", true);
    schemaPath.addLongIdentifier("schema-path", true);
    schemaPath.addLongIdentifier("schema-file", true);
    schemaPath.addLongIdentifier("schema-directory", true);
    parser.addArgument(schemaPath);

    numThreads = new IntegerArgument('t', "numThreads", false, 1, null,
         INFO_TRANSFORM_LDIF_ARG_DESC_NUM_THREADS.get(), 1, Integer.MAX_VALUE,
         1);
    numThreads.addLongIdentifier("num-threads", true);
    parser.addArgument(numThreads);

    processDNs = new BooleanArgument('d', "processDNs",
         INFO_TRANSFORM_LDIF_ARG_DESC_PROCESS_DNS.get());
    processDNs.addLongIdentifier("process-dns", true);
    parser.addArgument(processDNs);


    // Ensure that at least one kind of transformation was requested.
    parser.addRequiredArgumentSet(scrambleAttribute, sequentialAttribute,
         replaceValuesAttribute, addAttributeName, renameAttributeFrom,
         flattenBaseDN, moveSubtreeFrom, redactAttribute, excludeAttribute,
         excludeEntryBaseDN, excludeEntryScope, excludeEntryFilter,
         excludeChangeType, excludeRecordsWithoutChangeType);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // Ideally, exactly one of the targetLDIF and targetToStandardOutput
    // arguments should always be provided.  But in order to preserve backward
    // compatibility with a legacy scramble-ldif tool, we will allow both to be
    // omitted if either --scrambleAttribute or --sequentialArgument is
    // provided.  In that case, the path of the output file will be the path of
    // the first input file with ".scrambled" appended to it.
    if (! (targetLDIF.isPresent() || targetToStandardOutput.isPresent()))
    {
      if (! (scrambleAttribute.isPresent() || sequentialAttribute.isPresent()))
      {
        throw new ArgumentException(ERR_TRANSFORM_LDIF_MISSING_TARGET_ARG.get(
             targetLDIF.getIdentifierString(),
             targetToStandardOutput.getIdentifierString()));
      }
    }


    // Make sure that the --renameAttributeFrom and --renameAttributeTo
    // arguments were provided an equal number of times.
    final int renameFromOccurrences = renameAttributeFrom.getNumOccurrences();
    final int renameToOccurrences = renameAttributeTo.getNumOccurrences();
    if (renameFromOccurrences != renameToOccurrences)
    {
      throw new ArgumentException(
           ERR_TRANSFORM_LDIF_ARG_COUNT_MISMATCH.get(
                renameAttributeFrom.getIdentifierString(),
                renameAttributeTo.getIdentifierString()));
    }


    // Make sure that the --moveSubtreeFrom and --moveSubtreeTo arguments were
    // provided an equal number of times.
    final int moveFromOccurrences = moveSubtreeFrom.getNumOccurrences();
    final int moveToOccurrences = moveSubtreeTo.getNumOccurrences();
    if (moveFromOccurrences != moveToOccurrences)
    {
      throw new ArgumentException(
           ERR_TRANSFORM_LDIF_ARG_COUNT_MISMATCH.get(
                moveSubtreeFrom.getIdentifierString(),
                moveSubtreeTo.getIdentifierString()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    final Schema schema;
    try
    {
      schema = getSchema();
    }
    catch (final LDAPException le)
    {
      wrapErr(0, MAX_OUTPUT_LINE_LENGTH, le.getMessage());
      return le.getResultCode();
    }


    // If an encryption passphrase file is provided, then get the passphrase
    // from it.
    String encryptionPassphrase = null;
    if (encryptionPassphraseFile.isPresent())
    {
      try
      {
        encryptionPassphrase = ToolUtils.readEncryptionPassphraseFromFile(
             encryptionPassphraseFile.getValue());
      }
      catch (final LDAPException e)
      {
        wrapErr(0, MAX_OUTPUT_LINE_LENGTH, e.getMessage());
        return e.getResultCode();
      }
    }


    // Create the translators to use to apply the transformations.
    final ArrayList<LDIFReaderEntryTranslator> entryTranslators =
         new ArrayList<>(10);
    final ArrayList<LDIFReaderChangeRecordTranslator> changeRecordTranslators =
         new ArrayList<>(10);

    final AtomicLong excludedEntryCount = new AtomicLong(0L);
    createTranslators(entryTranslators, changeRecordTranslators,
         schema, excludedEntryCount);

    final AggregateLDIFReaderEntryTranslator entryTranslator =
         new AggregateLDIFReaderEntryTranslator(entryTranslators);
    final AggregateLDIFReaderChangeRecordTranslator changeRecordTranslator =
         new AggregateLDIFReaderChangeRecordTranslator(changeRecordTranslators);


    // Determine the path to the target file to be written.
    final File targetFile;
    if (targetLDIF.isPresent())
    {
      targetFile = targetLDIF.getValue();
    }
    else if (targetToStandardOutput.isPresent())
    {
      targetFile = null;
    }
    else
    {
      targetFile =
           new File(sourceLDIF.getValue().getAbsolutePath() + ".scrambled");
    }


    // Create the LDIF reader.
    final LDIFReader ldifReader;
    try
    {
      final InputStream inputStream;
      if (sourceLDIF.isPresent())
      {
        final ObjectPair<InputStream,String> p =
             ToolUtils.getInputStreamForLDIFFiles(sourceLDIF.getValues(),
                  encryptionPassphrase, getOut(), getErr());
        inputStream = p.getFirst();
        if ((encryptionPassphrase == null) && (p.getSecond() != null))
        {
          encryptionPassphrase = p.getSecond();
        }
      }
      else
      {
        inputStream = System.in;
      }

      ldifReader = new LDIFReader(inputStream, numThreads.getValue(),
           entryTranslator, changeRecordTranslator);
      if (schema != null)
      {
        ldifReader.setSchema(schema);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
           ERR_TRANSFORM_LDIF_ERROR_CREATING_LDIF_READER.get(
                StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    ResultCode resultCode = ResultCode.SUCCESS;
    OutputStream outputStream = null;
processingBlock:
    try
    {
      // Create the output stream to use to write the transformed data.
      try
      {
        if (targetFile == null)
        {
          outputStream = getOut();
        }
        else
        {
          outputStream =
               new FileOutputStream(targetFile, appendToTargetLDIF.isPresent());
        }

        if (encryptTarget.isPresent())
        {
          if (encryptionPassphrase == null)
          {
            encryptionPassphrase = ToolUtils.promptForEncryptionPassphrase(
                 false, true, getOut(), getErr());
          }

          outputStream = new PassphraseEncryptedOutputStream(
               encryptionPassphrase, outputStream);
        }

        if (compressTarget.isPresent())
        {
          outputStream = new GZIPOutputStream(outputStream);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
             ERR_TRANSFORM_LDIF_ERROR_CREATING_OUTPUT_STREAM.get(
                  targetFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)));
        resultCode = ResultCode.LOCAL_ERROR;
        break processingBlock;
      }


      // Read the source data one record at a time.  The transformations will
      // automatically be applied by the LDIF reader's translators, and even if
      // there are multiple reader threads, we're guaranteed to get the results
      // in the right order.
      long entriesWritten = 0L;
      while (true)
      {
        final LDIFRecord ldifRecord;
        try
        {
          ldifRecord = ldifReader.readLDIFRecord();
        }
        catch (final LDIFException le)
        {
          Debug.debugException(le);
          if (le.mayContinueReading())
          {
            wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                 ERR_TRANSFORM_LDIF_RECOVERABLE_MALFORMED_RECORD.get(
                      StaticUtils.getExceptionMessage(le)));
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = ResultCode.PARAM_ERROR;
            }
            continue;
          }
          else
          {
            wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                 ERR_TRANSFORM_LDIF_UNRECOVERABLE_MALFORMED_RECORD.get(
                      StaticUtils.getExceptionMessage(le)));
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = ResultCode.PARAM_ERROR;
            }
            break processingBlock;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_TRANSFORM_LDIF_UNEXPECTED_READ_ERROR.get(
                    StaticUtils.getExceptionMessage(e)));
          resultCode = ResultCode.LOCAL_ERROR;
          break processingBlock;
        }


        // If the LDIF record is null, then we've run out of records so we're
        // done.
        if (ldifRecord == null)
        {
          break;
        }


        // Write the record to the output stream.
        try
        {
          if (ldifRecord instanceof PreEncodedLDIFEntry)
          {
            outputStream.write(
                 ((PreEncodedLDIFEntry) ldifRecord).getLDIFBytes());
          }
          else
          {
            final ByteStringBuffer buffer = getBuffer();
            if (wrapColumn.isPresent())
            {
              ldifRecord.toLDIF(buffer, wrapColumn.getValue());
            }
            else
            {
              ldifRecord.toLDIF(buffer, 0);
            }
            buffer.append(StaticUtils.EOL_BYTES);
            buffer.write(outputStream);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_TRANSFORM_LDIF_WRITE_ERROR.get(targetFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          resultCode = ResultCode.LOCAL_ERROR;
          break processingBlock;
        }


        // If we've written a multiple of 1000 entries, print a progress
        // message.
        entriesWritten++;
        if ((! targetToStandardOutput.isPresent()) &&
            ((entriesWritten % 1000L) == 0))
        {
          final long numExcluded = excludedEntryCount.get();
          if (numExcluded > 0L)
          {
            wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
                 INFO_TRANSFORM_LDIF_WROTE_ENTRIES_WITH_EXCLUDED.get(
                      entriesWritten, numExcluded));
          }
          else
          {
            wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
                 INFO_TRANSFORM_LDIF_WROTE_ENTRIES_NONE_EXCLUDED.get(
                      entriesWritten));
          }
        }
      }


      if (! targetToStandardOutput.isPresent())
      {
        final long numExcluded = excludedEntryCount.get();
        if (numExcluded > 0L)
        {
          wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
               INFO_TRANSFORM_LDIF_COMPLETE_WITH_EXCLUDED.get(entriesWritten,
                    numExcluded));
        }
        else
        {
          wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
               INFO_TRANSFORM_LDIF_COMPLETE_NONE_EXCLUDED.get(entriesWritten));
        }
      }
    }
    finally
    {
      if (outputStream != null)
      {
        try
        {
          outputStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_TRANSFORM_LDIF_ERROR_CLOSING_OUTPUT_STREAM.get(
                    targetFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          if (resultCode == ResultCode.SUCCESS)
          {
            resultCode = ResultCode.LOCAL_ERROR;
          }
        }
      }

      try
      {
        ldifReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        // We can ignore this.
      }
    }


    return resultCode;
  }



  /**
   * Retrieves the schema that should be used for processing.
   *
   * @return  The schema that was created.
   *
   * @throws  LDAPException  If a problem is encountered while retrieving the
   *                         schema.
   */
  @Nullable()
  private Schema getSchema()
          throws LDAPException
  {
    // If any schema paths were specified, then load the schema only from those
    // paths.
    if (schemaPath.isPresent())
    {
      final ArrayList<File> schemaFiles = new ArrayList<>(10);
      for (final File path : schemaPath.getValues())
      {
        if (path.isFile())
        {
          schemaFiles.add(path);
        }
        else
        {
          final TreeMap<String,File> fileMap = new TreeMap<>();
          for (final File schemaDirFile : path.listFiles())
          {
            final String name = schemaDirFile.getName();
            if (schemaDirFile.isFile() && name.toLowerCase().endsWith(".ldif"))
            {
              fileMap.put(name, schemaDirFile);
            }
          }
          schemaFiles.addAll(fileMap.values());
        }
      }

      if (schemaFiles.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_TRANSFORM_LDIF_NO_SCHEMA_FILES.get(
                  schemaPath.getIdentifierString()));
      }
      else
      {
        try
        {
          return Schema.getSchema(schemaFiles);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_TRANSFORM_LDIF_ERROR_LOADING_SCHEMA.get(
                    StaticUtils.getExceptionMessage(e)));
        }
      }
    }
    else
    {
      // If the INSTANCE_ROOT environment variable is set and it refers to a
      // directory that has a config/schema subdirectory that has one or more
      // schema files in it, then read the schema from that directory.
      try
      {
        final String instanceRootStr =
             StaticUtils.getEnvironmentVariable("INSTANCE_ROOT");
        if (instanceRootStr != null)
        {
          final File instanceRoot = new File(instanceRootStr);
          final File configDir = new File(instanceRoot, "config");
          final File schemaDir = new File(configDir, "schema");
          if (schemaDir.exists())
          {
            final TreeMap<String,File> fileMap = new TreeMap<>();
            for (final File schemaDirFile : schemaDir.listFiles())
            {
              final String name = schemaDirFile.getName();
              if (schemaDirFile.isFile() &&
                  name.toLowerCase().endsWith(".ldif"))
              {
                fileMap.put(name, schemaDirFile);
              }
            }

            if (! fileMap.isEmpty())
            {
              return Schema.getSchema(new ArrayList<>(fileMap.values()));
            }
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }


    // If we've gotten here, then just return null and the tool will try to use
    // the default standard schema.
    return null;
  }



  /**
   * Creates the entry and change record translators that will be used to
   * perform the transformations.
   *
   * @param  entryTranslators         A list to which all created entry
   *                                  translators should be written.
   * @param  changeRecordTranslators  A list to which all created change record
   *                                  translators should be written.
   * @param  schema                   The schema to use when processing.
   * @param  excludedEntryCount       A counter used to keep track of the number
   *                                  of entries that have been excluded from
   *                                  the result set.
   */
  private void createTranslators(
       @NotNull final List<LDIFReaderEntryTranslator> entryTranslators,
       @NotNull final List<LDIFReaderChangeRecordTranslator>
            changeRecordTranslators,
       @Nullable final Schema schema,
       @NotNull final AtomicLong excludedEntryCount)
  {
    if (scrambleAttribute.isPresent())
    {
      final Long seed;
      if (randomSeed.isPresent())
      {
        seed = randomSeed.getValue().longValue();
      }
      else
      {
        seed = null;
      }

      final ScrambleAttributeTransformation t =
           new ScrambleAttributeTransformation(schema, seed,
                processDNs.isPresent(), scrambleAttribute.getValues(),
                scrambleJSONField.getValues());
      entryTranslators.add(t);
      changeRecordTranslators.add(t);
    }

    if (sequentialAttribute.isPresent())
    {
      final long initialValue;
      if (initialSequentialValue.isPresent())
      {
        initialValue = initialSequentialValue.getValue().longValue();
      }
      else
      {
        initialValue = 0L;
      }

      final long incrementAmount;
      if (sequentialValueIncrement.isPresent())
      {
        incrementAmount = sequentialValueIncrement.getValue().longValue();
      }
      else
      {
        incrementAmount = 1L;
      }

      for (final String attrName : sequentialAttribute.getValues())
      {


        final ReplaceWithCounterTransformation t =
             new ReplaceWithCounterTransformation(schema, attrName,
                  initialValue, incrementAmount,
                  textBeforeSequentialValue.getValue(),
                  textAfterSequentialValue.getValue(), processDNs.isPresent());
        entryTranslators.add(t);
      }
    }

    if (replaceValuesAttribute.isPresent())
    {
      final ReplaceAttributeTransformation t =
           new ReplaceAttributeTransformation(schema,
                replaceValuesAttribute.getValue(),
                replacementValue.getValues());
      entryTranslators.add(t);
    }

    if (addAttributeName.isPresent())
    {
      final AddAttributeTransformation t = new AddAttributeTransformation(
           schema, addAttributeBaseDN.getValue(), addAttributeScope.getValue(),
           addAttributeFilter.getValue(),
           new Attribute(addAttributeName.getValue(), schema,
                addAttributeValue.getValues()),
           (! addToExistingValues.isPresent()));
      entryTranslators.add(t);
    }

    if (renameAttributeFrom.isPresent())
    {
      final Iterator<String> renameFromIterator =
           renameAttributeFrom.getValues().iterator();
      final Iterator<String> renameToIterator =
           renameAttributeTo.getValues().iterator();
      while (renameFromIterator.hasNext())
      {
        final RenameAttributeTransformation t =
             new RenameAttributeTransformation(schema,
                  renameFromIterator.next(), renameToIterator.next(),
                  processDNs.isPresent());
        entryTranslators.add(t);
        changeRecordTranslators.add(t);
      }
    }

    if (flattenBaseDN.isPresent())
    {
      final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
           schema, flattenBaseDN.getValue(),
           flattenAddOmittedRDNAttributesToEntry.isPresent(),
           flattenAddOmittedRDNAttributesToRDN.isPresent(),
           flattenExcludeFilter.getValue());
      entryTranslators.add(t);
    }

    if (moveSubtreeFrom.isPresent())
    {
      final Iterator<DN> moveFromIterator =
           moveSubtreeFrom.getValues().iterator();
      final Iterator<DN> moveToIterator = moveSubtreeTo.getValues().iterator();
      while (moveFromIterator.hasNext())
      {
        final MoveSubtreeTransformation t =
             new MoveSubtreeTransformation(moveFromIterator.next(),
                  moveToIterator.next());
        entryTranslators.add(t);
        changeRecordTranslators.add(t);
      }
    }

    if (redactAttribute.isPresent())
    {
      final RedactAttributeTransformation t = new RedactAttributeTransformation(
           schema, processDNs.isPresent(),
           (! hideRedactedValueCount.isPresent()), redactAttribute.getValues());
      entryTranslators.add(t);
      changeRecordTranslators.add(t);
    }

    if (excludeAttribute.isPresent())
    {
      final ExcludeAttributeTransformation t =
           new ExcludeAttributeTransformation(schema,
                excludeAttribute.getValues());
      entryTranslators.add(t);
      changeRecordTranslators.add(t);
    }

    if (excludeEntryBaseDN.isPresent() || excludeEntryScope.isPresent() ||
        excludeEntryFilter.isPresent())
    {
      final ExcludeEntryTransformation t = new ExcludeEntryTransformation(
           schema, excludeEntryBaseDN.getValue(), excludeEntryScope.getValue(),
           excludeEntryFilter.getValue(),
           (! excludeNonMatchingEntries.isPresent()), excludedEntryCount);
      entryTranslators.add(t);
    }

    if (excludeChangeType.isPresent())
    {
      final Set<ChangeType> changeTypes = EnumSet.noneOf(ChangeType.class);
      for (final String changeTypeName : excludeChangeType.getValues())
      {
        changeTypes.add(ChangeType.forName(changeTypeName));
      }

      changeRecordTranslators.add(
           new ExcludeChangeTypeTransformation(changeTypes));
    }

    if (excludeRecordsWithoutChangeType.isPresent())
    {
      entryTranslators.add(new ExcludeAllEntriesTransformation());
    }

    entryTranslators.add(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(4));

    examples.put(
         new String[]
         {
           "--sourceLDIF", "input.ldif",
           "--targetLDIF", "scrambled.ldif",
           "--scrambleAttribute", "givenName",
           "--scrambleAttribute", "sn",
           "--scrambleAttribute", "cn",
           "--numThreads", "10",
           "--schemaPath", "/ds/config/schema",
           "--processDNs"
         },
         INFO_TRANSFORM_LDIF_EXAMPLE_SCRAMBLE.get());

    examples.put(
         new String[]
         {
           "--sourceLDIF", "input.ldif",
           "--targetLDIF", "sequential.ldif",
           "--sequentialAttribute", "uid",
           "--initialSequentialValue", "1",
           "--sequentialValueIncrement", "1",
           "--textBeforeSequentialValue", "user.",
           "--numThreads", "10",
           "--schemaPath", "/ds/config/schema",
           "--processDNs"
         },
         INFO_TRANSFORM_LDIF_EXAMPLE_SEQUENTIAL.get());

    examples.put(
         new String[]
         {
           "--sourceLDIF", "input.ldif",
           "--targetLDIF", "added-organization.ldif",
           "--addAttributeName", "o",
           "--addAttributeValue", "Example Corp.",
           "--addAttributeFilter", "(objectClass=person)",
           "--numThreads", "10",
           "--schemaPath", "/ds/config/schema"
         },
         INFO_TRANSFORM_LDIF_EXAMPLE_ADD.get());

    examples.put(
         new String[]
         {
           "--sourceLDIF", "input.ldif",
           "--targetLDIF", "rebased.ldif",
           "--moveSubtreeFrom", "o=example.com",
           "--moveSubtreeTo", "dc=example,dc=com",
           "--numThreads", "10",
           "--schemaPath", "/ds/config/schema"
         },
         INFO_TRANSFORM_LDIF_EXAMPLE_REBASE.get());

    return examples;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translate(@NotNull final Entry original,
                         final long firstLineNumber)
         throws LDIFException
  {
    final ByteStringBuffer buffer = getBuffer();
    if (wrapColumn.isPresent())
    {
      original.toLDIF(buffer, wrapColumn.getValue());
    }
    else
    {
      original.toLDIF(buffer, 0);
    }
    buffer.append(StaticUtils.EOL_BYTES);

    return new PreEncodedLDIFEntry(original, buffer.toByteArray());
  }



  /**
   * Retrieves a byte string buffer that can be used to perform LDIF encoding.
   *
   * @return  A byte string buffer that can be used to perform LDIF encoding.
   */
  @NotNull()
  private ByteStringBuffer getBuffer()
  {
    ByteStringBuffer buffer = byteStringBuffers.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      byteStringBuffers.set(buffer);
    }
    else
    {
      buffer.clear();
    }

    return buffer;
  }
}
