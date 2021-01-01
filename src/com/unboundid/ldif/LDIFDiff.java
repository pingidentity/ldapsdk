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
package com.unboundid.ldif;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
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
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldif.LDIFMessages.*;



/**
 * This class provides a command-line tool that can be used to identify the
 * differences between two LDIF files.  The output will itself be an LDIF file
 * that contains the add, delete, and modify operations that can be processed
 * against the source LDIF file to result in the target LDIF file.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFDiff
       extends CommandLineTool
{
  /**
   * The server root directory for the Ping Identity Directory Server (or
   * related Ping Identity server product) that contains this tool, if
   * applicable.
   */
  @Nullable private static final File PING_SERVER_ROOT =
       InternalSDKHelper.getPingIdentityServerRoot();



  /**
   * Indicates whether the tool is running as part of a Ping Identity Directory
   * Server (or related Ping Identity Server Product) installation.
   */
  private static final boolean PING_SERVER_AVAILABLE =
       (PING_SERVER_ROOT != null);



  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The change type name used to indicate that add operations should be
   * included in the output.
   */
  @NotNull
  private static final String CHANGE_TYPE_ADD = "add";



  /**
   * The change type name used to indicate that delete operations should be
   * included in the output.
   */
  @NotNull private static final String CHANGE_TYPE_DELETE = "delete";



  /**
   * The change type name used to indicate that modify operations should be
   * included in the output.
   */
  @NotNull private static final String CHANGE_TYPE_MODIFY = "modify";



  // The completion message for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // Encryption passphrases used thus far.
  @NotNull private final List<char[]> encryptionPassphrases;

  // The command-line arguments supported by this tool.
  @Nullable private BooleanArgument compressOutput;
  @Nullable private BooleanArgument encryptOutput;
  @Nullable private BooleanArgument excludeNoUserModificationAttributes;
  @Nullable private BooleanArgument includeOperationalAttributes;
  @Nullable private BooleanArgument nonReversibleModifications;
  @Nullable private BooleanArgument overwriteExistingOutputLDIF;
  @Nullable private BooleanArgument singleValueChanges;
  @Nullable private BooleanArgument stripTrailingSpaces;
  @Nullable private FileArgument outputEncryptionPassphraseFile;
  @Nullable private FileArgument outputLDIF;
  @Nullable private FileArgument schemaPath;
  @Nullable private FileArgument sourceEncryptionPassphraseFile;
  @Nullable private FileArgument sourceLDIF;
  @Nullable private FileArgument targetEncryptionPassphraseFile;
  @Nullable private FileArgument targetLDIF;
  @Nullable private FilterArgument excludeFilter;
  @Nullable private FilterArgument includeFilter;
  @Nullable private StringArgument changeType;
  @Nullable private StringArgument excludeAttribute;
  @Nullable private StringArgument includeAttribute;



  /**
   * Invokes this tool with the provided set of command-line arguments.
   *
   * @param  args  The set of arguments provided to this tool.  It may be
   *               empty but must not be {@code null}.
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
   * Invokes this tool with the provided set of command-line arguments, using
   * the given output and error streams.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The set of arguments provided to this tool.  It may be
   *               empty but must not be {@code null}.
   *
   * @return  A result code indicating the status of processing.  Any result
   *          code other than {@link ResultCode#SUCCESS} should be considered
   *          an error.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDIFDiff tool = new LDIFDiff(out, err);
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
  public LDIFDiff(@Nullable final OutputStream out,
                  @Nullable final OutputStream err)
  {
    super(out, err);

    encryptionPassphrases = new ArrayList<>(5);
    completionMessage = new AtomicReference<>();

    compressOutput = null;
    encryptOutput = null;
    excludeNoUserModificationAttributes = null;
    includeOperationalAttributes = null;
    nonReversibleModifications = null;
    overwriteExistingOutputLDIF = null;
    singleValueChanges = null;
    stripTrailingSpaces = null;
    outputEncryptionPassphraseFile = null;
    outputLDIF = null;
    schemaPath = null;
    sourceEncryptionPassphraseFile = null;
    sourceLDIF = null;
    targetEncryptionPassphraseFile = null;
    targetLDIF = null;
    changeType = null;
    excludeFilter = null;
    includeFilter = null;
    excludeAttribute = null;
    includeAttribute = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldif-diff";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDIF_DIFF_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    final List<String> messages = new ArrayList<>(3);
    messages.add(INFO_LDIF_DIFF_TOOL_DESCRIPTION_2.get());
    messages.add(INFO_LDIF_DIFF_TOOL_DESCRIPTION_3.get());

    if (PING_SERVER_AVAILABLE)
    {
      messages.add(INFO_LDIF_DIFF_TOOL_DESCRIPTION_4_PING_SERVER.get(
           getToolName()));
    }
    else
    {
      messages.add(INFO_LDIF_DIFF_TOOL_DESCRIPTION_4_STANDALONE.get(
           getToolName()));
    }

    return messages;
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
    sourceLDIF = new FileArgument('s', "sourceLDIF", true, 1, null,
         INFO_LDIF_DIFF_ARG_DESC_SOURCE_LDIF.get(), true, true, true, false);
    sourceLDIF.addLongIdentifier("source-ldif", true);
    sourceLDIF.addLongIdentifier("source", true);
    sourceLDIF.addLongIdentifier("sourceFile", true);
    sourceLDIF.addLongIdentifier("source-file", true);
    sourceLDIF.addLongIdentifier("sourceLDIFFile", true);
    sourceLDIF.addLongIdentifier("source-ldif-file", true);
    sourceLDIF.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_SOURCE.get());
    parser.addArgument(sourceLDIF);


    final String sourcePWDesc;
    if (PING_SERVER_AVAILABLE)
    {
      sourcePWDesc = INFO_LDIF_DIFF_ARG_DESC_SOURCE_PW_FILE_PING_SERVER.get();
    }
    else
    {
      sourcePWDesc = INFO_LDIF_DIFF_ARG_DESC_SOURCE_PW_FILE_STANDALONE.get();
    }
    sourceEncryptionPassphraseFile = new FileArgument(null,
         "sourceEncryptionPassphraseFile", false, 1, null, sourcePWDesc, true,
         true, true, false);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "source-encryption-passphrase-file", true);
    sourceEncryptionPassphraseFile.addLongIdentifier("sourcePassphraseFile",
         true);
    sourceEncryptionPassphraseFile.addLongIdentifier("source-passphrase-file",
         true);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "sourceEncryptionPasswordFile", true);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "source-encryption-password-file", true);
    sourceEncryptionPassphraseFile.addLongIdentifier("sourcePasswordFile",
         true);
    sourceEncryptionPassphraseFile.addLongIdentifier("source-password-file",
         true);
    sourceEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_SOURCE.get());
    parser.addArgument(sourceEncryptionPassphraseFile);


    targetLDIF = new FileArgument('t', "targetLDIF", true, 1, null,
         INFO_LDIF_DIFF_ARG_DESC_TARGET_LDIF.get(), true, true, true, false);
    targetLDIF.addLongIdentifier("target-ldif", true);
    targetLDIF.addLongIdentifier("target", true);
    targetLDIF.addLongIdentifier("targetFile", true);
    targetLDIF.addLongIdentifier("target-file", true);
    targetLDIF.addLongIdentifier("targetLDIFFile", true);
    targetLDIF.addLongIdentifier("target-ldif-file", true);
    targetLDIF.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_TARGET.get());
    parser.addArgument(targetLDIF);


    final String targetPWDesc;
    if (PING_SERVER_AVAILABLE)
    {
      targetPWDesc = INFO_LDIF_DIFF_ARG_DESC_TARGET_PW_FILE_PING_SERVER.get();
    }
    else
    {
      targetPWDesc = INFO_LDIF_DIFF_ARG_DESC_TARGET_PW_FILE_STANDALONE.get();
    }
    targetEncryptionPassphraseFile = new FileArgument(null,
         "targetEncryptionPassphraseFile", false, 1, null, targetPWDesc, true,
         true, true, false);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "target-encryption-passphrase-file", true);
    targetEncryptionPassphraseFile.addLongIdentifier("targetPassphraseFile",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier("target-passphrase-file",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "targetEncryptionPasswordFile", true);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "target-encryption-password-file", true);
    targetEncryptionPassphraseFile.addLongIdentifier("targetPasswordFile",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier("target-password-file",
         true);
    targetEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_TARGET.get());
    parser.addArgument(targetEncryptionPassphraseFile);


    outputLDIF = new FileArgument('o', "outputLDIF", false, 1, null,
         INFO_LDIF_DIFF_ARG_DESC_OUTPUT_LDIF.get(), false, true, true, false);
    outputLDIF.addLongIdentifier("output-ldif", true);
    outputLDIF.addLongIdentifier("output", true);
    outputLDIF.addLongIdentifier("outputFile", true);
    outputLDIF.addLongIdentifier("output-file", true);
    outputLDIF.addLongIdentifier("outputLDIFFile", true);
    outputLDIF.addLongIdentifier("output-ldif-file", true);
    outputLDIF.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputLDIF);


    compressOutput = new BooleanArgument(null, "compressOutput", 1,
         INFO_LDIF_DIFF_ARG_DESC_COMPRESS_OUTPUT.get());
    compressOutput.addLongIdentifier("compress-output", true);
    compressOutput.addLongIdentifier("compress", true);
    compressOutput.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_OUTPUT.get());
    parser.addArgument(compressOutput);


    encryptOutput = new BooleanArgument(null, "encryptOutput", 1,
         INFO_LDIF_DIFF_ARG_DESC_ENCRYPT_OUTPUT.get());
    encryptOutput.addLongIdentifier("encrypt-output", true);
    encryptOutput.addLongIdentifier("encrypt", true);
    encryptOutput.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_OUTPUT.get());
    parser.addArgument(encryptOutput);


    outputEncryptionPassphraseFile = new FileArgument(null,
         "outputEncryptionPassphraseFile", false, 1, null,
         INFO_LDIF_DIFF_ARG_DESC_OUTPUT_PW_FILE.get(), true, true, true, false);
    outputEncryptionPassphraseFile.addLongIdentifier(
         "output-encryption-passphrase-file", true);
    outputEncryptionPassphraseFile.addLongIdentifier("outputPassphraseFile",
         true);
    outputEncryptionPassphraseFile.addLongIdentifier("output-passphrase-file",
         true);
    outputEncryptionPassphraseFile.addLongIdentifier(
         "outputEncryptionPasswordFile", true);
    outputEncryptionPassphraseFile.addLongIdentifier(
         "output-encryption-password-file", true);
    outputEncryptionPassphraseFile.addLongIdentifier("outputPasswordFile",
         true);
    outputEncryptionPassphraseFile.addLongIdentifier("output-password-file",
         true);
    outputEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputEncryptionPassphraseFile);


    overwriteExistingOutputLDIF = new BooleanArgument('O',
         "overwriteExistingOutputLDIF", 1,
         INFO_LDIF_DIFF_ARG_DESC_OVERWRITE_EXISTING.get());
    overwriteExistingOutputLDIF.addLongIdentifier(
         "overwrite-existing-output-ldif", true);
    overwriteExistingOutputLDIF.addLongIdentifier(
         "overwriteExistingOutputFile", true);
    overwriteExistingOutputLDIF.addLongIdentifier(
         "overwrite-existing-output-file", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwriteExistingOutput",
         true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite-existing-output",
         true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwriteExisting", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite-existing", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwriteOutputLDIF", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite-output-ldif",
         true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwriteOutputFile", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite-output-file",
         true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwriteOutput", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite-output", true);
    overwriteExistingOutputLDIF.addLongIdentifier("overwrite", true);
    overwriteExistingOutputLDIF.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_OUTPUT.get());
    parser.addArgument(overwriteExistingOutputLDIF);


    changeType = new StringArgument(null, "changeType", false, 0,
         INFO_LDIF_DIFF_ARG_PLACEHOLDER_CHANGE_TYPE.get(),
         INFO_LDIF_DIFF_ARG_DESC_CHANGE_TYPE.get(),
         StaticUtils.setOf(
              CHANGE_TYPE_ADD,
              CHANGE_TYPE_DELETE,
              CHANGE_TYPE_MODIFY),
         Collections.unmodifiableList(Arrays.asList(
              CHANGE_TYPE_ADD,
              CHANGE_TYPE_DELETE,
              CHANGE_TYPE_MODIFY)));
    changeType.addLongIdentifier("change-type", true);
    changeType.addLongIdentifier("operationType", true);
    changeType.addLongIdentifier("operation-type", true);
    changeType.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(changeType);


    includeFilter = new FilterArgument(null, "includeFilter", false, 0, null,
         INFO_LDIF_DIFF_ARG_DESC_INCLUDE_FILTER.get());
    includeFilter.addLongIdentifier("include-filter", true);
    includeFilter.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(includeFilter);


    excludeFilter = new FilterArgument(null, "excludeFilter", false, 0, null,
         INFO_LDIF_DIFF_ARG_DESC_EXCLUDE_FILTER.get());
    excludeFilter.addLongIdentifier("exclude-filter", true);
    excludeFilter.setArgumentGroupName(INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(excludeFilter);


    includeAttribute = new StringArgument(null, "includeAttribute", false, 0,
         INFO_LDIF_DIFF_ARG_PLACEHOLDER_ATTRIBUTE.get(),
         INFO_LDIF_DIFF_ARG_DESC_INCLUDE_ATTRIBUTE.get());
    includeAttribute.addLongIdentifier("include-attribute", true);
    includeAttribute.addLongIdentifier("includeAttr", true);
    includeAttribute.addLongIdentifier("include-attr", true);
    includeAttribute.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(includeAttribute);


    excludeAttribute = new StringArgument(null, "excludeAttribute", false, 0,
         INFO_LDIF_DIFF_ARG_PLACEHOLDER_ATTRIBUTE.get(),
         INFO_LDIF_DIFF_ARG_DESC_EXCLUDE_ATTRIBUTE.get());
    excludeAttribute.addLongIdentifier("exclude-attribute", true);
    excludeAttribute.addLongIdentifier("excludeAttr", true);
    excludeAttribute.addLongIdentifier("exclude-attr", true);
    excludeAttribute.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(excludeAttribute);


    includeOperationalAttributes = new BooleanArgument('i',
         "includeOperationalAttributes", 1,
         INFO_LDIF_DIFF_ARG_DESC_INCLUDE_OPERATIONAL.get());
    includeOperationalAttributes.addLongIdentifier(
         "include-operational-attributes", true);
    includeOperationalAttributes.addLongIdentifier("includeOperational", true);
    includeOperationalAttributes.addLongIdentifier("include-operational", true);
    includeOperationalAttributes.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(includeOperationalAttributes);


    excludeNoUserModificationAttributes = new BooleanArgument('e',
         "excludeNoUserModificationAttributes", 1,
         INFO_LDIF_DIFF_ARG_DESC_EXCLUDE_NO_USER_MOD.get());
    excludeNoUserModificationAttributes.addLongIdentifier(
         "exclude-no-user-modification-attributes", true);
    excludeNoUserModificationAttributes.addLongIdentifier(
         "excludeNoUserModAttributes", true);
    excludeNoUserModificationAttributes.addLongIdentifier(
         "exclude-no-user-mod-attributes", true);
    excludeNoUserModificationAttributes.addLongIdentifier(
         "excludeNoUserModification", true);
    excludeNoUserModificationAttributes.addLongIdentifier(
         "exclude-no-user-modification", true);
    excludeNoUserModificationAttributes.addLongIdentifier("excludeNoUserMod",
         true);
    excludeNoUserModificationAttributes.addLongIdentifier("exclude-no-user-mod",
         true);
    excludeNoUserModificationAttributes.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(excludeNoUserModificationAttributes);


    nonReversibleModifications = new BooleanArgument(null,
         "nonReversibleModifications", 1,
         INFO_LDIF_DIFF_ARG_DESC_NON_REVERSIBLE_MODS.get());
    nonReversibleModifications.addLongIdentifier("non-reversible-modifications",
         true);
    nonReversibleModifications.addLongIdentifier("nonReversibleMods", true);
    nonReversibleModifications.addLongIdentifier("non-reversible-mods", true);
    nonReversibleModifications.addLongIdentifier("nonReversible", true);
    nonReversibleModifications.addLongIdentifier("non-reversible", true);
    nonReversibleModifications.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(nonReversibleModifications);


    singleValueChanges = new BooleanArgument('S', "singleValueChanges", 1,
         INFO_LDIF_DIFF_ARG_DESC_SINGLE_VALUE_CHANGES.get());
    singleValueChanges.addLongIdentifier("single-value-changes", true);
    parser.addArgument(singleValueChanges);


    stripTrailingSpaces = new BooleanArgument(null, "stripTrailingSpaces", 1,
         INFO_LDIF_DIFF_ARG_DESC_STRIP_TRAILING_SPACES.get());
    stripTrailingSpaces.addLongIdentifier("strip-trailing-spaces", true);
    stripTrailingSpaces.addLongIdentifier("ignoreTrailingSpaces", true);
    stripTrailingSpaces.addLongIdentifier("ignore-trailing-spaces", true);
    stripTrailingSpaces.setArgumentGroupName(
         INFO_LDIF_DIFF_ARG_GROUP_CONTENT.get());
    parser.addArgument(stripTrailingSpaces);


    final String schemaPathDesc;
    if (PING_SERVER_AVAILABLE)
    {
      schemaPathDesc = INFO_LDIF_DIFF_ARG_DESC_SCHEMA_PATH_PING_SERVER.get();
    }
    else
    {
      schemaPathDesc = INFO_LDIF_DIFF_ARG_DESC_SCHEMA_PATH_STANDALONE.get();
    }
    schemaPath = new FileArgument(null, "schemaPath", false, 0, null,
         schemaPathDesc, true, true, false, false);
    schemaPath.addLongIdentifier("schema-path", true);
    schemaPath.addLongIdentifier("schemaFile", true);
    schemaPath.addLongIdentifier("schema-file", true);
    schemaPath.addLongIdentifier("schemaDirectory", true);
    schemaPath.addLongIdentifier("schema-directory", true);
    schemaPath.addLongIdentifier("schema", true);
    parser.addArgument(schemaPath);


    parser.addDependentArgumentSet(compressOutput, outputLDIF);
    parser.addDependentArgumentSet(encryptOutput, outputLDIF);
    parser.addDependentArgumentSet(outputEncryptionPassphraseFile, outputLDIF);
    parser.addDependentArgumentSet(overwriteExistingOutputLDIF, outputLDIF);

    parser.addDependentArgumentSet(outputEncryptionPassphraseFile,
         encryptOutput);

    parser.addExclusiveArgumentSet(includeAttribute, excludeAttribute);
    parser.addExclusiveArgumentSet(includeAttribute,
         includeOperationalAttributes);

    parser.addExclusiveArgumentSet(includeFilter, excludeFilter);

    parser.addDependentArgumentSet(excludeNoUserModificationAttributes,
         includeOperationalAttributes);

    parser.addExclusiveArgumentSet(nonReversibleModifications,
         singleValueChanges);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If the LDIF file exists and either compressOutput or encryptOutput is
    // present, then the overwrite argument must also be present.
    final File outputFile = outputLDIF.getValue();
    if ((outputFile != null) && outputFile.exists() &&
         (compressOutput.isPresent() || encryptOutput.isPresent()) &&
         (! overwriteExistingOutputLDIF.isPresent()))
    {
      throw new ArgumentException(
           ERR_LDIF_DIFF_APPEND_WITH_COMPRESSION_OR_ENCRYPTION.get(
                compressOutput.getIdentifierString(),
                encryptOutput.getIdentifierString(),
                overwriteExistingOutputLDIF.getIdentifierString()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the change types to use for processing.
    final Set<ChangeType> changeTypes = EnumSet.noneOf(ChangeType.class);
    for (final String value : changeType.getValues())
    {
      switch (StaticUtils.toLowerCase(value))
      {
        case CHANGE_TYPE_ADD:
          changeTypes.add(ChangeType.ADD);
          break;
        case CHANGE_TYPE_DELETE:
          changeTypes.add(ChangeType.DELETE);
          break;
        case CHANGE_TYPE_MODIFY:
          changeTypes.add(ChangeType.MODIFY);
          break;
      }
    }


    // Get the schema to use when performing LDIF processing.
    final Schema schema;
    try
    {
      if (schemaPath.isPresent())
      {
        schema = getSchema(schemaPath.getValues());
      }
      else if (PING_SERVER_AVAILABLE)
      {
        schema = getSchema(Collections.singletonList(StaticUtils.constructPath(
             PING_SERVER_ROOT, "config", "schema")));
      }
      else
      {
        schema = Schema.getDefaultStandardSchema();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_LDIF_DIFF_CANNOT_GET_SCHEMA.get(
                StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    // Identify the sets of include and exclude attributes.
    final Set<String> includeAttrs;
    if (includeAttribute.isPresent())
    {
      final Set<String> s = new HashSet<>();
      for (final String includeAttr : includeAttribute.getValues())
      {
        final String lowerName = StaticUtils.toLowerCase(includeAttr);
        s.add(lowerName);

        final AttributeTypeDefinition at = schema.getAttributeType(lowerName);
        if (at != null)
        {
          s.add(StaticUtils.toLowerCase(at.getOID()));
          for (final String name : at.getNames())
          {
            s.add(StaticUtils.toLowerCase(name));
          }
        }
      }
      includeAttrs = Collections.unmodifiableSet(s);
    }
    else
    {
      includeAttrs = Collections.emptySet();
    }

    final Set<String> excludeAttrs;
    if (excludeAttribute.isPresent())
    {
      final Set<String> s = new HashSet<>();
      for (final String excludeAttr : excludeAttribute.getValues())
      {
        final String lowerName = StaticUtils.toLowerCase(excludeAttr);
        s.add(lowerName);

        final AttributeTypeDefinition at = schema.getAttributeType(lowerName);
        if (at != null)
        {
          s.add(StaticUtils.toLowerCase(at.getOID()));
          for (final String name : at.getNames())
          {
            s.add(StaticUtils.toLowerCase(name));
          }
        }
      }
      excludeAttrs = Collections.unmodifiableSet(s);
    }
    else
    {
      excludeAttrs = Collections.emptySet();
    }


    // Read the source and target LDIF files into memory.
    final TreeMap<DN,Entry> sourceEntries;
    try
    {
      sourceEntries = readEntries(sourceLDIF.getValue(),
           sourceEncryptionPassphraseFile.getValue(), schema);
      out(INFO_LDIF_DIFF_READ_FROM_SOURCE_LDIF.get(
           sourceLDIF.getValue().getName(), sourceEntries.size()));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_LDIF_DIFF_CANNOT_READ_SOURCE_LDIF.get(
                sourceLDIF.getValue().getAbsolutePath(), e.getMessage()));
      return e.getResultCode();
    }

    final TreeMap<DN,Entry> targetEntries;
    try
    {
      targetEntries = readEntries(targetLDIF.getValue(),
           targetEncryptionPassphraseFile.getValue(), schema);
      out(INFO_LDIF_DIFF_READ_FROM_TARGET_LDIF.get(
           targetLDIF.getValue().getName(), targetEntries.size()));
      out();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_LDIF_DIFF_CANNOT_READ_TARGET_LDIF.get(
                targetLDIF.getValue().getAbsolutePath(), e.getMessage()));
      return e.getResultCode();
    }


    final String outputFilePath;
    if (outputLDIF.isPresent())
    {
      outputFilePath = outputLDIF.getValue().getAbsolutePath();
    }
    else
    {
      outputFilePath = "{STDOUT}";
    }


    // Open the output file for writing.
    long addCount = 0L;
    long deleteCount = 0L;
    long modifyCount = 0L;
    try (OutputStream outputStream = openOutputStream();
         LDIFWriter ldifWriter = new LDIFWriter(outputStream))
    {
      // First, identify any entries that have been added (that is, entries in
      // the target set that are not in the source set), and write them to the
      // output file.
      if (changeTypes.contains(ChangeType.ADD))
      {
        try
        {
          addCount = writeAdds(sourceEntries, targetEntries, ldifWriter,
               schema, includeAttrs, excludeAttrs);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIF_DIFF_ERROR_WRITING_OUTPUT.get(outputFilePath,
                    e.getMessage()));
          return e.getResultCode();
        }
      }


      // Next, identify any entries that have been modified (that is, entries
      // that exist in both sets, but are different between those sets), and
      // write them to the output file.  We'll write modifies after adds because
      // that allows modifications to reference newly created entries, and we'll
      // write modifies before deletes because that allows modifications to
      // remove references to entries that will be removed.
      if (changeTypes.contains(ChangeType.MODIFY))
      {
        try
        {
          modifyCount = writeModifications(sourceEntries, targetEntries,
               ldifWriter, schema, includeAttrs, excludeAttrs);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIF_DIFF_ERROR_WRITING_OUTPUT.get(outputFilePath,
                    e.getMessage()));
          return e.getResultCode();
        }
      }


      // Finally, identify any deletes (entries that were only in the set of
      // source entries) and write them to the output file.
      if (changeTypes.contains(ChangeType.DELETE))
      {
        try
        {
          deleteCount = writeDeletes(sourceEntries, targetEntries, ldifWriter,
               schema, includeAttrs, excludeAttrs);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIF_DIFF_ERROR_WRITING_OUTPUT.get(outputFilePath,
                    e.getMessage()));
          return e.getResultCode();
        }
      }


      // If we've gotten here, then everything was successful.
      ldifWriter.flush();
      logCompletionMessage(false, INFO_LDIF_DIFF_COMPLETED.get());
      if (changeTypes.contains(ChangeType.ADD))
      {
        out(INFO_LDIF_DIFF_COMPLETED_ADD_COUNT.get(addCount));
      }

      if (changeTypes.contains(ChangeType.MODIFY))
      {
        out(INFO_LDIF_DIFF_COMPLETED_MODIFY_COUNT.get(modifyCount));
      }

      if (changeTypes.contains(ChangeType.DELETE))
      {
        out(INFO_LDIF_DIFF_COMPLETED_DELETE_COUNT.get(deleteCount));
      }

      return ResultCode.SUCCESS;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_LDIF_DIFF_CANNOT_OPEN_OUTPUT.get(outputFilePath,
                e.getMessage()));
      return e.getResultCode();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_LDIF_DIFF_ERROR_WRITING_OUTPUT.get(outputFilePath,
                StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }
  }



  /**
   * Retrieves the schema contained in the specified paths.
   *
   * @param  paths  The paths to use to access the schema.
   *
   * @return  The schema read from the specified files.
   *
   * @throws  Exception  If a problem is encountered while loading the schema.
   */
  @NotNull()
  private static Schema getSchema(@NotNull final List<File> paths)
          throws Exception
  {
    final Set<File> schemaFiles = new LinkedHashSet<>();
    for (final File f : paths)
    {
      if (f.exists())
      {
        if (f.isFile())
        {
          schemaFiles.add(f);
        }
        else if (f.isDirectory())
        {
          final TreeMap<String,File> sortedFiles = new TreeMap<>();
          for (final File fileInDir : f.listFiles())
          {
            if (fileInDir.isFile())
            {
              sortedFiles.put(fileInDir.getName(), fileInDir);
            }
          }

          schemaFiles.addAll(sortedFiles.values());
        }
      }
    }

    return Schema.getSchema(new ArrayList<>(schemaFiles));
  }



  /**
   * Reads all of the entries in the specified LDIF file into a map.
   *
   * @param  ldifFile   The path to the LDIF file to read.  It must not be
   *                    {@code null}.
   * @param  encPWFile  The path to the file containing the passphrase used to
   *                    encrypt the LDIF file.  It may be {@code null} if the
   *                    LDIF file is not encrypted, or if the encryption key is
   *                    to be obtained through an alternate means.
   * @param  schema     The schema to use when reading the LDIF file.  It must
   *                    not be {@code null}.
   *
   * @return  The map of entries read from the file.
   *
   * @throws  LDAPException  If a problem occurs while attempting to read the
   *                         entries.
   */
  @NotNull()
  private TreeMap<DN,Entry> readEntries(@NotNull final File ldifFile,
                                        @Nullable final File encPWFile,
                                        @NotNull final Schema schema)
          throws LDAPException
  {
    if (encPWFile != null)
    {
      try
      {
        addPassphrase(getPasswordFileReader().readPassword(encPWFile));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_OPEN_PW_FILE.get(encPWFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    InputStream inputStream = null;
    try
    {
      try
      {
        inputStream = new FileInputStream(ldifFile);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_OPEN_LDIF_FILE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      try
      {
        final ObjectPair<InputStream,char[]> p =
             ToolUtils.getPossiblyPassphraseEncryptedInputStream(inputStream,
                  encryptionPassphrases, (encPWFile == null),
                  INFO_LDIF_DIFF_PROMPT_FOR_ENC_PW.get(ldifFile.getName()),
                  ERR_LDIF_DIFF_PROMPT_WRONG_ENC_PW.get(), getOut(), getErr());
        inputStream = p.getFirst();
        addPassphrase(p.getSecond());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_DECRYPT_LDIF_FILE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      try
      {
        inputStream =
             ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_DECOMPRESS_LDIF_FILE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      try (LDIFReader reader = new LDIFReader(inputStream))
      {
        reader.setSchema(schema);
        if (stripTrailingSpaces.isPresent())
        {
          reader.setTrailingSpaceBehavior(TrailingSpaceBehavior.STRIP);
        }
        else
        {
          reader.setTrailingSpaceBehavior(TrailingSpaceBehavior.REJECT);
        }

        final TreeMap<DN,Entry> entryMap = new TreeMap<>();
        while (true)
        {
          final Entry entry = reader.readEntry();
          if (entry == null)
          {
            break;
          }

          entryMap.put(entry.getParsedDN(), entry);
        }

        return entryMap;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_ERROR_READING_OR_DECODING.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    finally
    {
      if (inputStream != null)
      {
        try
        {
          inputStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Updates the list of encryption passphrases with the provided passphrase, if
   * it is not already present.
   *
   * @param  passphrase  The passphrase to be added.  It may optionally be
   *                     {@code null} (in which case no action will be taken).
   */
  private void addPassphrase(@Nullable final char[] passphrase)
  {
    if (passphrase == null)
    {
      return;
    }

    for (final char[] existingPassphrase : encryptionPassphrases)
    {
      if (Arrays.equals(existingPassphrase, passphrase))
      {
        return;
      }
    }

    encryptionPassphrases.add(passphrase);
  }



  /**
   * Opens the output stream to use to write the identified differences.
   *
   * @return  The output stream that was opened.
   *
   * @throws  LDAPException  If a problem is encountered while opening the
   *                         output stream.
   */
  @NotNull()
  private OutputStream openOutputStream()
          throws LDAPException
  {
    if (! outputLDIF.isPresent())
    {
      return getOut();
    }

    OutputStream outputStream = null;
    boolean closeOutputStream = true;
    try
    {
      try
      {

        outputStream = new FileOutputStream(outputLDIF.getValue(),
             (! overwriteExistingOutputLDIF.isPresent()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_OPEN_OUTPUT_FILE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      if (encryptOutput.isPresent())
      {
        try
        {
          final char[] passphrase;
          if (outputEncryptionPassphraseFile.isPresent())
          {
            passphrase = getPasswordFileReader().readPassword(
                 outputEncryptionPassphraseFile.getValue());
          }
          else
          {
            passphrase = ToolUtils.promptForEncryptionPassphrase(false, true,
                 INFO_LDIF_DIFF_PROMPT_OUTPUT_FILE_ENC_PW.get(),
                 INFO_LDIF_DIFF_CONFIRM_OUTPUT_FILE_ENC_PW.get(), getOut(),
                 getErr()).toCharArray();
          }

          outputStream = new PassphraseEncryptedOutputStream(passphrase,
               outputStream, null, true, true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDIF_DIFF_CANNOT_ENCRYPT_OUTPUT_FILE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      if (compressOutput.isPresent())
      {
        try
        {
          outputStream = new GZIPOutputStream(outputStream);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDIF_DIFF_CANNOT_COMPRESS_OUTPUT_FILE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      closeOutputStream = false;
      return outputStream;
    }
    finally
    {
      if (closeOutputStream && (outputStream != null))
      {
        try
        {
          outputStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Writes add change records for all entries contained in the given target
   * entry map that are not in the source entry map.
   *
   * @param  sourceEntries  The map of entries read from the source LDIF file.
   *                        It must not be {@code null}.
   * @param  targetEntries  The map of entries read from the target LDIF file.
   *                        It must not be {@code null}.
   * @param  writer         The LDIF writer to use to write any changes.  It
   *                        must not be {@ocde null} and it must be open.
   * @param  schema         The schema to use to identify operational
   *                        attributes.  It must not be {@ocde null}.
   * @param  includeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be included in the
   *                        entry.  It must not be {@ocde null} but may be
   *                        empty.  All values must be formatted entirely in
   *                        lowercase.
   * @param  excludeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be excluded from the
   *                        entry.  It must not be {@code null} but may be
   *                        empty.  All values must be formatted entirely in
   *                        lowercase.
   *
   * @return  The number of added entries that were identified during
   *          processing.
   *
   * @throws  LDAPException  If a problem is encountered while writing the ad
   *                         change records.
   */
  private long writeAdds(@NotNull final TreeMap<DN,Entry> sourceEntries,
                         @NotNull final TreeMap<DN,Entry> targetEntries,
                         @NotNull final LDIFWriter writer,
                         @NotNull final Schema schema,
                         @NotNull final Set<String> includeAttrs,
                         @NotNull final Set<String> excludeAttrs)
          throws LDAPException
  {
    long addCount = 0L;

    for (final Map.Entry<DN,Entry> e : targetEntries.entrySet())
    {
      final DN entryDN = e.getKey();
      final Entry entry = e.getValue();
      if (! sourceEntries.containsKey(entryDN))
      {
        if (! includeEntryByFilter(schema, entry))
        {
          continue;
        }

        final Entry paredEntry = pareEntry(entry, schema, includeAttrs,
             excludeAttrs);
        if (paredEntry == null)
        {
          continue;
        }

        try
        {
          writer.writeChangeRecord(new LDIFAddChangeRecord(paredEntry),
               INFO_LDIF_DIFF_ADD_COMMENT.get());
          addCount++;
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_WRITE_ADD_FOR_ENTRY.get(entry.getDN(),
                  StaticUtils.getExceptionMessage(ex)),
             ex);
        }
      }
    }

    return addCount;
  }



  /**
   * Indicates whether the specified entry may be included in the output based
   * on the include filter and exclude filter configuration.
   *
   * @param  schema   The schema to use when making the determination.  It must
   *                  not be {@code null}.
   * @param  entries  The entries for which to make the determination.  It must
   *                  not be {@code null} or empty.
   *
   * @return  {@code true} if the entry should be included, or {@code false} if]
   *          not.
   */
  private boolean includeEntryByFilter(@NotNull final Schema schema,
                                       @NotNull final Entry... entries)
  {
    for (final Entry entry : entries)
    {
      for (final Filter f : excludeFilter.getValues())
      {
        try
        {
          if (f.matchesEntry(entry, schema))
          {
            return false;
          }
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
        }
      }
    }

    if (includeFilter.isPresent())
    {
      for (final Entry entry : entries)
      {
        for (final Filter f : includeFilter.getValues())
        {
          try
          {
            if (f.matchesEntry(entry, schema))
            {
              return true;
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }

      return false;
    }

    return true;
  }



  /**
   * Creates a pared-down copy of the provided entry based on the requested
   * set of options.
   *
   * @param  entry         The entry to be pared down.  It must not be
   *                       {@code null}.
   * @param  schema        The schema to use during processing.  It must not be
   *                       {@ocde null}.
   * @param  includeAttrs  A set containing all names and OIDs for all attribute
   *                       types that should be included in the entry.  It must
   *                       not be {@ocde null} but may be empty.  All values
   *                       must be formatted entirely in lowercase.
   * @param  excludeAttrs  A set containing all names and OIDs for all attribute
   *                       types that should be excluded from the entry.  It
   *                       must not be {@code null} but may be empty.  All
   *                       values must be formatted entirely in lowercase.
   *
   * @return  A pared-down copy of the provided entry, or {@code null} if the
   *          pared-down entry would not include any attributes.
   */
  @Nullable()
  private Entry pareEntry(@NotNull final Entry entry,
                          @NotNull final Schema schema,
                          @NotNull final Set<String> includeAttrs,
                          @NotNull final Set<String> excludeAttrs)
  {
    final List<Attribute> paredAttributeList = new ArrayList<>();
    for (final Attribute a : entry.getAttributes())
    {
      final String baseName = StaticUtils.toLowerCase(a.getBaseName());
      if (excludeAttrs.contains(baseName))
      {
        continue;
      }

      if ((! includeAttrs.isEmpty()) && (! includeAttrs.contains(baseName)))
      {
        continue;
      }

      final AttributeTypeDefinition at = schema.getAttributeType(baseName);
      if ((at != null) && at.isOperational())
      {
        if (! includeOperationalAttributes.isPresent())
        {
          continue;
        }

        if (at.isNoUserModification() &&
             excludeNoUserModificationAttributes.isPresent())
        {
          continue;
        }
      }

      paredAttributeList.add(a);
    }

    if (paredAttributeList.isEmpty())
    {
      return null;
    }

    return new Entry(entry.getDN(), paredAttributeList);
  }



  /**
   * Identifies entries that exist in both the source and target maps and
   * determines whether there are any changes between them.
   *
   * @param  sourceEntries  The map of entries read from the source LDIF file.
   *                        It must not be {@code null}.
   * @param  targetEntries  The map of entries read from the target LDIF file.
   *                        It must not be {@code null}.
   * @param  writer         The LDIF writer to use to write any changes.  It
   *                        must not be {@ocde null} and it must be open.
   * @param  schema         The schema to use to identify operational
   *                        attributes.  It must not be {@ocde null}.
   * @param  includeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be included in the
   *                        set of modifications.  It must not be {@ocde null}
   *                        but may be empty.  All values must be formatted
   *                        entirely in lowercase.
   * @param  excludeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be excluded from the
   *                        set of modifications.  It must not be {@ocde null}
   *                        but may be empty.  All values must be formatted
   *                        entirely in lowercase.
   *
   * @return  The number of modified entries that were identified during
   *          processing.
   *
   * @throws  LDAPException  If a problem is encountered while writing
   *                         modified entries.
   */
  private long writeModifications(
                    @NotNull final TreeMap<DN,Entry> sourceEntries,
                    @NotNull final TreeMap<DN,Entry> targetEntries,
                    @NotNull final LDIFWriter writer,
                    @NotNull final Schema schema,
                    @NotNull final Set<String> includeAttrs,
                    @NotNull final Set<String> excludeAttrs)
          throws LDAPException
  {
    long modCount = 0L;

    for (final Map.Entry<DN,Entry> sourceMapEntry : sourceEntries.entrySet())
    {
      final DN sourceDN = sourceMapEntry.getKey();

      final Entry targetEntry = targetEntries.get(sourceDN);
      if (targetEntry == null)
      {
        continue;
      }

      final Entry sourceEntry = sourceMapEntry.getValue();

      if (! includeEntryByFilter(schema, sourceEntry, targetEntry))
      {
        continue;
      }

      final List<Modification> mods = Entry.diff(sourceEntry, targetEntry,
           false, (! nonReversibleModifications.isPresent()), true);
      if (writeModifiedEntry(sourceDN, mods, writer, schema, includeAttrs,
           excludeAttrs))
      {
        modCount++;
      }
    }

    return modCount;
  }



  /**
   * Writes a modified entry to the LDIF writer.
   *
   * @param  dn            The DN of the entry to write.  It must not be
   *                       {@code null}.
   * @param  mods          The modifications to be written.
   * @param  writer        The LDIF writer to use to write the modify change
   *                       record(s).
   * @param  schema        The schema to use to identify operational attributes.
   *                       It must not be {@code null}.
   * @param  includeAttrs  A set containing all names and OIDs for all attribute
   *                       types that should be included in the set of
   *                       modifications.  It must not be {@ocde null} but may
   *                       be empty.  All values must be formatted entirely in
   *                       lowercase.
   * @param  excludeAttrs  A set containing all names and OIDs for all attribute
   *                       types that should be excluded from the set of
   *                       modifications.  It must not be {@ocde null} but may
   *                       be empty.  All values must be formatted entirely in
   *                       lowercase.
   *
   * @return  {@code true} if one or more modify change records were written, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while trying to write the
   *                         modifications.
   */
  private boolean writeModifiedEntry(@NotNull final DN dn,
                                     @NotNull final List<Modification> mods,
                                     @NotNull final LDIFWriter writer,
                                     @NotNull final Schema schema,
                                     @NotNull final Set<String> includeAttrs,
                                     @NotNull final Set<String> excludeAttrs)
          throws LDAPException
  {
    if (mods.isEmpty())
    {
      return false;
    }

    final List<Modification> paredMods = new ArrayList<>(mods.size());
    for (final Modification m : mods)
    {
      final Attribute a = m.getAttribute();
      final String baseName = StaticUtils.toLowerCase(a.getBaseName());
      if (excludeAttrs.contains(baseName))
      {
        continue;
      }

      if ((! includeAttrs.isEmpty()) && ! includeAttrs.contains(baseName))
      {
        continue;
      }

      final AttributeTypeDefinition at =
           schema.getAttributeType(a.getBaseName());
      if ((at != null) && at.isOperational())
      {
        if (includeOperationalAttributes.isPresent())
        {
          if (at.isNoUserModification())
          {
            if (! excludeNoUserModificationAttributes.isPresent())
            {
              paredMods.add(m);
            }
          }
          else
          {
            paredMods.add(m);
          }
        }
      }
      else
      {
        paredMods.add(m);
      }
    }

    if (paredMods.isEmpty())
    {
      return false;
    }

    try
    {
      if (singleValueChanges.isPresent())
      {
        for (final Modification m : paredMods)
        {
          final Attribute a = m.getAttribute();
          if (a.size() > 1)
          {
            for (final byte[] value : a.getValueByteArrays())
            {
              writer.writeChangeRecord(new LDIFModifyChangeRecord(dn.toString(),
                   new Modification(m.getModificationType(),
                        m.getAttributeName(), value)));
            }
          }
          else
          {
            writer.writeChangeRecord(new LDIFModifyChangeRecord(dn.toString(),
                 m));
          }
        }
      }
      else
      {
        writer.writeChangeRecord(
             new LDIFModifyChangeRecord(dn.toString(), paredMods),
             INFO_LDIF_DIFF_MODIFY_COMMENT.get());
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDIF_DIFF_CANNOT_WRITE_MODS_TO_ENTRY.get(dn.toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    return true;
  }



  /**
   * Writes delete change records for all entries contained in the given source
   * entry map that are not in the target entry map.
   *
   * @param  sourceEntries  The map of entries read from the source LDIF file.
   *                        It must not be {@code null}.
   * @param  targetEntries  The map of entries read from the target LDIF file.
   *                        It must not be {@code null}.
   * @param  writer         The LDIF writer to use to write any changes.  It
   *                        must not be {@ocde null} and it must be open.
   * @param  schema         The schema to use to identify operational
   *                        attributes.  It must not be {@ocde null}.
   * @param  includeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be included in the
   *                        entry.  It must not be {@ocde null} but may be
   *                        empty.  All values must be formatted entirely in
   *                        lowercase.
   * @param  excludeAttrs   A set containing all names and OIDs for all
   *                        attribute types that should be excluded from the
   *                        entry.  It must not be {@code null} but may be
   *                        empty.  All values must be formatted entirely in
   *                        lowercase.
   *
   * @return  The number of deleted entries that were identified during
   *          processing.
   *
   * @throws  LDAPException  If a problem is encountered while writing the
   *                         delete change records.
   */
  private long writeDeletes(@NotNull final TreeMap<DN,Entry> sourceEntries,
                            @NotNull final TreeMap<DN,Entry> targetEntries,
                            @NotNull final LDIFWriter writer,
                            @NotNull final Schema schema,
                            @NotNull final Set<String> includeAttrs,
                            @NotNull final Set<String> excludeAttrs)
          throws LDAPException
  {
    long deleteCount = 0L;

    for (final Map.Entry<DN,Entry> e : sourceEntries.descendingMap().entrySet())
    {
      final DN entryDN = e.getKey();
      final Entry entry = e.getValue();
      if (! targetEntries.containsKey(entryDN))
      {
        if (! includeEntryByFilter(schema, entry))
        {
          continue;
        }

        final Entry paredEntry = pareEntry(entry, schema, includeAttrs,
             excludeAttrs);
        if (paredEntry == null)
        {
          continue;
        }

        try
        {
          final String comment = INFO_LDIF_DIFF_DELETE_COMMENT.get() +
               StaticUtils.EOL + paredEntry.toLDIFString(75);
          writer.writeChangeRecord(
               new LDIFDeleteChangeRecord(paredEntry.getDN()), comment);
          deleteCount++;
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIF_DIFF_CANNOT_WRITE_DELETE_FOR_ENTRY.get(entry.getDN(),
                  StaticUtils.getExceptionMessage(ex)),
             ex);
        }
      }
    }

    return deleteCount;
  }



  /**
   * Writes the provided message and sets it as the completion message.
   *
   * @param  isError  Indicates whether the message should be written to
   *                  standard error rather than standard output.
   * @param  message  The message to be written.
   */
  private void logCompletionMessage(final boolean isError,
                                    @NotNull final String message)
  {
    completionMessage.compareAndSet(null, message);

    if (isError)
    {
      wrapErr(0, WRAP_COLUMN, message);
    }
    else
    {
      wrapOut(0, WRAP_COLUMN, message);
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
         new String[]
         {
           "--sourceLDIF", "actual.ldif",
           "--targetLDIF", "desired.ldif",
           "--outputLDIF", "diff.ldif"
         },
         INFO_LDIF_DIFF_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--sourceLDIF", "actual.ldif",
           "--targetLDIF", "desired.ldif",
           "--outputLDIF", "diff.ldif",
           "--includeOperationalAttributes",
           "--excludeNoUserModificationAttributes",
           "--nonReversibleModifications"
         },
         INFO_LDIF_DIFF_EXAMPLE_2.get());

    return examples;
  }
}
