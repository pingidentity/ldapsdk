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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
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
import com.unboundid.util.Validator;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;

import static com.unboundid.ldif.LDIFMessages.*;



/**
 * This class provides a command-line tool that can be used to apply a set of
 * changes to data in an LDIF file.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFModify
       extends CommandLineTool
{
  /**
   * The server root directory for the Ping Identity Directory Server (or
   * related Ping Identity server product) that contains this tool, if
   * applicable.
   */
  @NotNull private static final File PING_SERVER_ROOT =
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



  // The completion message for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // Encryption passphrases used thus far.
  @NotNull private final List<char[]> inputEncryptionPassphrases;

  // The command-line arguments supported by this tool.
  @Nullable private BooleanArgument compressTarget;
  @Nullable private BooleanArgument doNotWrap;
  @Nullable private BooleanArgument encryptTarget;
  @Nullable private BooleanArgument ignoreDeletesOfNonexistentEntries;
  @Nullable private BooleanArgument ignoreDuplicateDeletes;
  @Nullable private BooleanArgument ignoreModifiesOfNonexistentEntries;
  @Nullable private BooleanArgument lenientModifications;
  @Nullable private BooleanArgument strictModifications;
  @Nullable private BooleanArgument noSchemaCheck;
  @Nullable private BooleanArgument stripTrailingSpaces;
  @Nullable private BooleanArgument suppressComments;
  @Nullable private FileArgument changesEncryptionPassphraseFile;
  @Nullable private FileArgument changesLDIF;
  @Nullable private FileArgument sourceEncryptionPassphraseFile;
  @Nullable private FileArgument sourceLDIF;
  @Nullable private FileArgument targetEncryptionPassphraseFile;
  @Nullable private FileArgument targetLDIF;
  @Nullable private IntegerArgument wrapColumn;

  // Variables that may be used by support for a legacy implementation.
  @Nullable private LDIFReader changesReader;
  @Nullable private LDIFReader sourceReader;
  @Nullable private LDIFWriter targetWriter;
  @Nullable private List<String> errorMessages;



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
    final LDIFModify tool = new LDIFModify(out, err);
    return tool.runTool(args);
  }



  /**
   * Invokes this tool with the provided readers and writer.  This method is
   * primarily intended for legacy backward compatibility with the Ping Identity
   * Directory Server and does not provide access to all functionality offered
   * by this tool.
   *
   * @param  sourceReader   An LDIF reader that may be used to read the entries
   *                        to be updated.  It must not be {@code null}.  Note
   *                        this the reader will be closed when the tool
   *                        completes.
   * @param  changesReader  An LDIF reader that may be used to read the changes
   *                        to apply.  It must not be {@code null}.  Note that
   *                        this reader will be closed when the tool completes.
   * @param  targetWriter   An LDIF writer that may be used to write the updated
   *                        entries.  It must not be {@code null}.  Note that
   *                        this writer will be closed when the tool completes.
   * @param  errorMessages  A list that will be updated with any errors
   *                        encountered during processing.  It must not be
   *                        {@code null} and must be updatable.
   *
   * @return  {@code true} if processing completed successfully, or
   *          {@code false} if one or more errors were encountered.
   */
  public static boolean main(@NotNull final LDIFReader sourceReader,
                             @NotNull final LDIFReader changesReader,
                             @NotNull final LDIFWriter targetWriter,
                             @NotNull final List<String> errorMessages)
  {
    Validator.ensureNotNull(sourceReader, changesReader, targetWriter,
         errorMessages);

    final LDIFModify tool = new LDIFModify(null, null);
    tool.sourceReader = sourceReader;
    tool.changesReader = changesReader;
    tool.targetWriter = targetWriter;
    tool.errorMessages = errorMessages;

    try
    {
      final ResultCode resultCode =
           tool.runTool("--suppressComments", "--lenientModifications");
      return (resultCode == ResultCode.SUCCESS);
    }
    finally
    {
      try
      {
        sourceReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      try
      {
        changesReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      try
      {
        targetWriter.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
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
  public LDIFModify(@Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();
    inputEncryptionPassphrases = new ArrayList<>(5);

    compressTarget = null;
    doNotWrap = null;
    encryptTarget = null;
    ignoreDeletesOfNonexistentEntries = null;
    ignoreDuplicateDeletes = null;
    ignoreModifiesOfNonexistentEntries = null;
    lenientModifications = null;
    noSchemaCheck = null;
    strictModifications = null;
    stripTrailingSpaces = null;
    suppressComments = null;
    changesEncryptionPassphraseFile = null;
    changesLDIF = null;
    sourceEncryptionPassphraseFile = null;
    sourceLDIF = null;
    targetEncryptionPassphraseFile = null;
    targetLDIF = null;
    wrapColumn = null;

    changesReader = null;
    sourceReader = null;
    targetWriter = null;
    errorMessages = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldifmodify";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDIFMODIFY_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Arrays.asList(
         INFO_LDIFMODIFY_TOOL_DESCRIPTION_2.get(),
         INFO_LDIFMODIFY_TOOL_DESCRIPTION_3.get(),
         INFO_LDIFMODIFY_TOOL_DESCRIPTION_4.get(),
         INFO_LDIFMODIFY_TOOL_DESCRIPTION_5.get());
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
    sourceLDIF = new FileArgument('s', "sourceLDIF", (sourceReader == null), 1,
         null, INFO_LDIFMODIFY_ARG_DESC_SOURCE_LDIF.get(), true, true, true,
         false);
    sourceLDIF.addLongIdentifier("source-ldif", true);
    sourceLDIF.addLongIdentifier("sourceFile", true);
    sourceLDIF.addLongIdentifier("source-file", true);
    sourceLDIF.addLongIdentifier("source", true);
    sourceLDIF.addLongIdentifier("inputLDIF", true);
    sourceLDIF.addLongIdentifier("input-ldif", true);
    sourceLDIF.addLongIdentifier("inputFile", true);
    sourceLDIF.addLongIdentifier("input-file", true);
    sourceLDIF.addLongIdentifier("input", true);
    sourceLDIF.addLongIdentifier("ldifFile", true);
    sourceLDIF.addLongIdentifier("ldif-file", true);
    sourceLDIF.addLongIdentifier("ldif", true);
    sourceLDIF.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(sourceLDIF);


    final String sourcePWDesc;
    if (PING_SERVER_AVAILABLE)
    {
      sourcePWDesc = INFO_LDIFMODIFY_ARG_DESC_SOURCE_PW_FILE_PING_SERVER.get();
    }
    else
    {
      sourcePWDesc = INFO_LDIFMODIFY_ARG_DESC_SOURCE_PW_FILE_STANDALONE.get();
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
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "inputEncryptionPassphraseFile", true);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "input-encryption-passphrase-file", true);
    sourceEncryptionPassphraseFile.addLongIdentifier("inputPassphraseFile",
         true);
    sourceEncryptionPassphraseFile.addLongIdentifier("input-passphrase-file",
         true);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "inputEncryptionPasswordFile", true);
    sourceEncryptionPassphraseFile.addLongIdentifier(
         "input-encryption-password-file", true);
    sourceEncryptionPassphraseFile.addLongIdentifier("inputPasswordFile", true);
    sourceEncryptionPassphraseFile.addLongIdentifier("input-password-file",
         true);
    sourceEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(sourceEncryptionPassphraseFile);


    changesLDIF = new FileArgument('m', "changesLDIF", (changesReader == null),
         1, null, INFO_LDIFMODIFY_ARG_DESC_CHANGES_LDIF.get(), true, true, true,
         false);
    changesLDIF.addLongIdentifier("changes-ldif", true);
    changesLDIF.addLongIdentifier("changesFile", true);
    changesLDIF.addLongIdentifier("changes-file", true);
    changesLDIF.addLongIdentifier("changes", true);
    changesLDIF.addLongIdentifier("updatesLDIF", true);
    changesLDIF.addLongIdentifier("updates-ldif", true);
    changesLDIF.addLongIdentifier("updatesFile", true);
    changesLDIF.addLongIdentifier("updates-file", true);
    changesLDIF.addLongIdentifier("updates", true);
    changesLDIF.addLongIdentifier("modificationsLDIF", true);
    changesLDIF.addLongIdentifier("modifications-ldif", true);
    changesLDIF.addLongIdentifier("modificationsFile", true);
    changesLDIF.addLongIdentifier("modifications-file", true);
    changesLDIF.addLongIdentifier("modifications", true);
    changesLDIF.addLongIdentifier("modsLDIF", true);
    changesLDIF.addLongIdentifier("mods-ldif", true);
    changesLDIF.addLongIdentifier("modsFile", true);
    changesLDIF.addLongIdentifier("mods-file", true);
    changesLDIF.addLongIdentifier("mods", true);
    changesLDIF.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(changesLDIF);


    final String changesPWDesc;
    if (PING_SERVER_AVAILABLE)
    {
      changesPWDesc =
           INFO_LDIFMODIFY_ARG_DESC_CHANGES_PW_FILE_PING_SERVER.get();
    }
    else
    {
      changesPWDesc = INFO_LDIFMODIFY_ARG_DESC_CHANGES_PW_FILE_STANDALONE.get();
    }
    changesEncryptionPassphraseFile = new FileArgument(null,
         "changesEncryptionPassphraseFile", false, 1, null, changesPWDesc, true,
         true, true, false);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "changes-encryption-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier("changesPassphraseFile",
         true);
    changesEncryptionPassphraseFile.addLongIdentifier("changes-passphrase-file",
         true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "changesEncryptionPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "changes-encryption-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier("changesPasswordFile",
         true);
    changesEncryptionPassphraseFile.addLongIdentifier("changes-password-file",
         true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updatesEncryptionPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updates-encryption-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updatesPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updates-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updatesEncryptionPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updates-encryption-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updatesPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "updates-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modificationsEncryptionPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modifications-encryption-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modificationsPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modifications-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modificationsEncryptionPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modifications-encryption-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modificationsPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modifications-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modsEncryptionPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "mods-encryption-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modsPassphraseFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "mods-passphrase-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modsEncryptionPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "mods-encryption-password-file", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "modsPasswordFile", true);
    changesEncryptionPassphraseFile.addLongIdentifier(
         "mods-password-file", true);
    changesEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(changesEncryptionPassphraseFile);


    stripTrailingSpaces = new BooleanArgument(null, "stripTrailingSpaces", 1,
         INFO_LDIFMODIFY_ARG_DESC_STRIP_TRAILING_SPACES.get());
    stripTrailingSpaces.addLongIdentifier("strip-trailing-spaces", true);
    stripTrailingSpaces.addLongIdentifier("ignoreTrailingSpaces", true);
    stripTrailingSpaces.addLongIdentifier("ignore-trailing-spaces", true);
    stripTrailingSpaces.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(stripTrailingSpaces);


    lenientModifications = new BooleanArgument(null, "lenientModifications", 1,
         INFO_LDIFMODIFY_ARG_DESC_LENIENT_MODIFICATIONS.get());
    lenientModifications.addLongIdentifier("lenient-modifications", true);
    lenientModifications.addLongIdentifier("lenientModification", true);
    lenientModifications.addLongIdentifier("lenient-modification", true);
    lenientModifications.addLongIdentifier("lenientMods", true);
    lenientModifications.addLongIdentifier("lenient-mods", true);
    lenientModifications.addLongIdentifier("lenientMod", true);
    lenientModifications.addLongIdentifier("lenient-mod", true);
    lenientModifications.addLongIdentifier("lenient", true);
    lenientModifications.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    lenientModifications.setHidden(true);
    parser.addArgument(lenientModifications);


    strictModifications = new BooleanArgument(null, "strictModifications", 1,
         INFO_LDIFMODIFY_ARG_DESC_STRICT_MODIFICATIONS.get());
    strictModifications.addLongIdentifier("strict-modifications", true);
    strictModifications.addLongIdentifier("strictModification", true);
    strictModifications.addLongIdentifier("strict-modification", true);
    strictModifications.addLongIdentifier("strictMods", true);
    strictModifications.addLongIdentifier("strict-mods", true);
    strictModifications.addLongIdentifier("strictMod", true);
    strictModifications.addLongIdentifier("strict-mod", true);
    strictModifications.addLongIdentifier("strict", true);
    strictModifications.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(strictModifications);


    ignoreDuplicateDeletes = new BooleanArgument(null, "ignoreDuplicateDeletes",
         1, INFO_LDIFMODIFY_ARG_DESC_IGNORE_DUPLICATE_DELETES.get());
    ignoreDuplicateDeletes.addLongIdentifier("ignore-duplicate-deletes", true);
    ignoreDuplicateDeletes.addLongIdentifier("ignoreRepeatedDeletes", true);
    ignoreDuplicateDeletes.addLongIdentifier("ignore-repeated-deletes", true);
    ignoreDuplicateDeletes.addLongIdentifier("ignoreRepeatDeletes", true);
    ignoreDuplicateDeletes.addLongIdentifier("ignore-repeat-deletes", true);
    ignoreDuplicateDeletes.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(ignoreDuplicateDeletes);


    ignoreDeletesOfNonexistentEntries = new BooleanArgument(null,
         "ignoreDeletesOfNonexistentEntries", 1,
         INFO_LDIFMODIFY_ARG_DESC_IGNORE_NONEXISTENT_DELETES.get());
    ignoreDeletesOfNonexistentEntries.addLongIdentifier(
         "ignore-deletes-of-nonexistent-entries", true);
    ignoreDeletesOfNonexistentEntries.addLongIdentifier(
         "ignoreNonexistentDeletes", true);
    ignoreDeletesOfNonexistentEntries.addLongIdentifier(
         "ignore-nonexistent-deletes", true);
    ignoreDeletesOfNonexistentEntries.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(ignoreDeletesOfNonexistentEntries);


    ignoreModifiesOfNonexistentEntries = new BooleanArgument(null,
         "ignoreModifiesOfNonexistentEntries", 1,
         INFO_LDIFMODIFY_ARG_DESC_IGNORE_NONEXISTENT_MODIFIES.get());
    ignoreModifiesOfNonexistentEntries.addLongIdentifier(
         "ignore-modifies-of-nonexistent-entries", true);
    ignoreModifiesOfNonexistentEntries.addLongIdentifier(
         "ignoreNonexistentModifies", true);
    ignoreModifiesOfNonexistentEntries.addLongIdentifier(
         "ignore-nonexistent-modifies", true);
    ignoreModifiesOfNonexistentEntries.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_INPUT.get());
    parser.addArgument(ignoreModifiesOfNonexistentEntries);


    targetLDIF = new FileArgument('t', "targetLDIF", (targetWriter == null), 1,
         null, INFO_LDIFMODIFY_ARG_DESC_TARGET_LDIF.get(), false, true, true,
         false);
    targetLDIF.addLongIdentifier("target-ldif", true);
    targetLDIF.addLongIdentifier("targetFile", true);
    targetLDIF.addLongIdentifier("target-file", true);
    targetLDIF.addLongIdentifier("target", true);
    targetLDIF.addLongIdentifier("outputLDIF", true);
    targetLDIF.addLongIdentifier("output-ldif", true);
    targetLDIF.addLongIdentifier("outputFile", true);
    targetLDIF.addLongIdentifier("output-file", true);
    targetLDIF.addLongIdentifier("output", true);
    targetLDIF.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(targetLDIF);


    compressTarget = new BooleanArgument(null, "compressTarget", 1,
         INFO_LDIFMODIFY_ARG_DESC_COMPRESS_TARGET.get());
    compressTarget.addLongIdentifier("compress-target", true);
    compressTarget.addLongIdentifier("compressOutput", true);
    compressTarget.addLongIdentifier("compress-output", true);
    compressTarget.addLongIdentifier("compress", true);
    compressTarget.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(compressTarget);


    encryptTarget = new BooleanArgument(null, "encryptTarget", 1,
         INFO_LDIFMODIFY_ARG_DESC_ENCRYPT_TARGET.get());
    encryptTarget.addLongIdentifier("encrypt-target", true);
    encryptTarget.addLongIdentifier("encryptOutput", true);
    encryptTarget.addLongIdentifier("encrypt-output", true);
    encryptTarget.addLongIdentifier("encrypt", true);
    encryptTarget.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(encryptTarget);


    targetEncryptionPassphraseFile = new FileArgument(null,
         "targetEncryptionPassphraseFile", false, 1, null,
         INFO_LDIFMODIFY_ARG_DESC_TARGET_PW_FILE.get(), true, true, true,
         false);
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
    targetEncryptionPassphraseFile.addLongIdentifier(
         "outputEncryptionPassphraseFile", true);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "output-encryption-passphrase-file", true);
    targetEncryptionPassphraseFile.addLongIdentifier("outputPassphraseFile",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier("output-passphrase-file",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "outputEncryptionPasswordFile", true);
    targetEncryptionPassphraseFile.addLongIdentifier(
         "output-encryption-password-file", true);
    targetEncryptionPassphraseFile.addLongIdentifier("outputPasswordFile",
         true);
    targetEncryptionPassphraseFile.addLongIdentifier("output-password-file",
         true);
    targetEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());

    parser.addArgument(targetEncryptionPassphraseFile);


    wrapColumn = new IntegerArgument(null, "wrapColumn", false, 1, null,
         INFO_LDIFMODIFY_ARG_DESC_WRAP_COLUMN.get(), 5, Integer.MAX_VALUE);
    wrapColumn.addLongIdentifier("wrap-column", true);
    wrapColumn.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(wrapColumn);


    doNotWrap = new BooleanArgument('T', "doNotWrap", 1,
         INFO_LDIFMODIFY_ARG_DESC_DO_NOT_WRAP.get());
    doNotWrap.addLongIdentifier("do-not-wrap", true);
    doNotWrap.addLongIdentifier("dontWrap", true);
    doNotWrap.addLongIdentifier("dont-wrap", true);
    doNotWrap.addLongIdentifier("noWrap", true);
    doNotWrap.addLongIdentifier("no-wrap", true);
    doNotWrap.setArgumentGroupName(INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(doNotWrap);


    suppressComments = new BooleanArgument(null, "suppressComments", 1,
         INFO_LDIFMODIFY_ARG_DESC_SUPPRESS_COMMENTS.get());
    suppressComments.addLongIdentifier("suppress-comments", true);
    suppressComments.addLongIdentifier("excludeComments", true);
    suppressComments.addLongIdentifier("exclude-comments", true);
    suppressComments.addLongIdentifier("noComments", true);
    suppressComments.addLongIdentifier("no-comments", true);
    suppressComments.setArgumentGroupName(
         INFO_LDIFMODIFY_ARG_GROUP_OUTPUT.get());
    parser.addArgument(suppressComments);


    noSchemaCheck = new BooleanArgument(null, "noSchemaCheck", 1,
         INFO_LDIFMODIFY_ARG_DESC_NO_SCHEMA_CHECK.get());
    noSchemaCheck.addLongIdentifier("no-schema-check", true);
    noSchemaCheck.setHidden(true);
    parser.addArgument(noSchemaCheck);


    parser.addExclusiveArgumentSet(lenientModifications, strictModifications);

    parser.addExclusiveArgumentSet(wrapColumn, doNotWrap);

    parser.addDependentArgumentSet(targetEncryptionPassphraseFile,
         encryptTarget);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Read all of the changes into memory.
    final Map<DN,List<LDIFChangeRecord>> addAndSubsequentChangeRecords =
         new TreeMap<>();
    final Map<DN,Boolean> deletedEntryDNs = new TreeMap<>();
    final Map<DN,List<LDIFModifyChangeRecord>> modifyChangeRecords =
         new HashMap<>();
    final Map<DN,ObjectPair<DN,List<LDIFChangeRecord>>>
         modifyDNAndSubsequentChangeRecords = new TreeMap<>();
    final AtomicReference<ResultCode> resultCode = new AtomicReference<>();
    try
    {
      readChangeRecords(addAndSubsequentChangeRecords, deletedEntryDNs,
           modifyChangeRecords, modifyDNAndSubsequentChangeRecords, resultCode);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      resultCode.compareAndSet(null, e.getResultCode());
      return resultCode.get();
    }


    boolean changesIgnored = false;
    LDIFReader ldifReader = null;
    LDIFWriter ldifWriter = null;
    final AtomicLong entriesRead = new AtomicLong(0L);
    final AtomicLong entriesUpdated = new AtomicLong(0L);
    try
    {
      // Open the source LDIF file for reading.
      try
      {
        ldifReader = getLDIFReader(sourceReader, sourceLDIF.getValue(),
             sourceEncryptionPassphraseFile.getValue());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        logCompletionMessage(true, e.getMessage());
        return e.getResultCode();
      }


      // Open the target LDIF file for writing.
      try
      {
        ldifWriter = getLDIFWriter(targetWriter);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        logCompletionMessage(true, e.getMessage());
        return e.getResultCode();
      }


      // Iterate through the source LDIF file and apply changes as appropriate.
      final StringBuilder comment = new StringBuilder();
      while (true)
      {
        final LDIFRecord sourceRecord;
        try
        {
          sourceRecord = ldifReader.readLDIFRecord();
        }
        catch (final LDIFException e)
        {
          Debug.debugException(e);

          if (e.mayContinueReading())
          {
            resultCode.compareAndSet(null, ResultCode.DECODING_ERROR);
            wrapErr(ERR_LDIFMODIFY_RECOVERABLE_DECODE_ERROR.get(
                 sourceLDIF.getValue(), StaticUtils.getExceptionMessage(e)));
            continue;
          }
          else
          {
            logCompletionMessage(true,
                 ERR_LDIFMODIFY_UNRECOVERABLE_DECODE_ERROR.get(
                      sourceLDIF.getValue(),
                      StaticUtils.getExceptionMessage(e)));
            return ResultCode.DECODING_ERROR;
          }
        }
        catch (final IOException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIFMODIFY_READ_ERROR.get(sourceLDIF.getValue(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }


        // If the record we read was null, then we've hit the end of the source
        // content.
        if (sourceRecord == null)
        {
          break;
        }


        // If the record we read was an entry, then apply changes to it.  If it
        // was not, then that's an error.
        comment.setLength(0);

        final LDIFRecord targetRecord;
        if (sourceRecord instanceof Entry)
        {
          entriesRead.incrementAndGet();
          targetRecord = updateEntry((Entry) sourceRecord,
               addAndSubsequentChangeRecords, deletedEntryDNs,
               modifyChangeRecords, modifyDNAndSubsequentChangeRecords, comment,
               resultCode, entriesUpdated);
        }
        else
        {
          targetRecord = sourceRecord;
          // NOTE:  We're using false for the isError flag in this case because
          // a better error will be recorded by the createChangeRecordComment
          // call below.
          appendComment(comment,
               ERR_LDIFMODIFY_COMMENT_SOURCE_RECORD_NOT_ENTRY.get(), false);

          final StringBuilder msgBuffer = new StringBuilder();
          createChangeRecordComment(msgBuffer,
               ERR_LDIFMODIFY_OUTPUT_SOURCE_RECORD_NOT_ENTRY.get(
                    sourceLDIF.getValue().getAbsolutePath()),
               sourceRecord, true);
          wrapErr(msgBuffer.toString());
          resultCode.compareAndSet(null, ResultCode.DECODING_ERROR);
        }


        // Write the potentially updated entry to the target LDIF file.  If the
        // target record is null, then that means the entry has been deleted,
        // but we still may want to write a comment about the deleted entry to
        // the target file.
        try
        {
          if (targetRecord == null)
          {
            if ((comment.length() > 0) && (! suppressComments.isPresent()))
            {
              writeLDIFComment(ldifWriter, comment, false);
            }
          }
          else
          {
            writeLDIFRecord(ldifWriter, targetRecord, comment);
          }
        }
        catch (final IOException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIFMODIFY_WRITE_ERROR.get(targetLDIF.getValue(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }
      }


      try
      {
        // If there are any remaining add records, then process them.
        final AtomicBoolean isUpdated = new AtomicBoolean();
        for (final List<LDIFChangeRecord> records :
             addAndSubsequentChangeRecords.values())
        {
          final Iterator<LDIFChangeRecord> iterator = records.iterator();
          final LDIFAddChangeRecord addChangeRecord =
               (LDIFAddChangeRecord) iterator.next();
          Entry entry = addChangeRecord.getEntryToAdd();
          comment.setLength(0);
          if (iterator.hasNext())
          {
            createChangeRecordComment(comment,
                 INFO_LDIFMODIFY_ADDING_ENTRY_WITH_MODS.get(), addChangeRecord,
                 false);
            while (iterator.hasNext())
            {
              entry = applyModification(entry,
                   (LDIFModifyChangeRecord) iterator.next(), isUpdated,
                   resultCode, comment);
            }
          }
          else
          {
            appendComment(comment,
                 INFO_LDIFMODIFY_ADDING_ENTRY_NO_MODS.get(), false);
          }

          writeLDIFRecord(ldifWriter, entry, comment);
          entriesUpdated.incrementAndGet();
        }


        // If there are any remaining DNs to delete, then those entries must not
        // have been in the source LDIF.
        for (final Map.Entry<DN,Boolean> e : deletedEntryDNs.entrySet())
        {
          if (e.getValue() == Boolean.FALSE)
          {
            if (ignoreDeletesOfNonexistentEntries.isPresent())
            {
              changesIgnored = true;
            }
            else
            {
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              writeLDIFComment(ldifWriter,
                   ERR_LDIFMODIFY_NO_SUCH_ENTRY_TO_DELETE.get(
                        e.getKey().toString()),
                   true);
            }
          }
        }


        // If there are any remaining modify change records, then those entries
        // must not have been in the source LDIF.
        for (final List<LDIFModifyChangeRecord> l :
             modifyChangeRecords.values())
        {
          for (final LDIFChangeRecord r : l)
          {
            if (ignoreModifiesOfNonexistentEntries.isPresent())
            {
              changesIgnored = true;
            }
            else
            {
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              comment.setLength(0);
              createChangeRecordComment(comment,
                   ERR_LDIFMODIFY_NO_SUCH_ENTRY_TO_MODIFY.get(), r, true);
              writeLDIFComment(ldifWriter, comment, false);
            }
          }
        }


        // If there are any remaining modify DN change records, then those
        // entries must not have been in the source LDIF.
        for (final ObjectPair<DN,List<LDIFChangeRecord>> l :
             modifyDNAndSubsequentChangeRecords.values())
        {
          for (final LDIFChangeRecord r : l.getSecond())
          {
            resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
            comment.setLength(0);
            if (r instanceof LDIFModifyDNChangeRecord)
            {
              createChangeRecordComment(comment,
                   ERR_LDIFMODIFY_NO_SUCH_ENTRY_TO_RENAME.get(), r, true);
            }
            else
            {
              createChangeRecordComment(comment,
                   ERR_LDIFMODIFY_NO_SUCH_ENTRY_TO_MODIFY.get(), r, true);
            }
            writeLDIFComment(ldifWriter, comment, false);
          }
        }
      }
      catch (final IOException e)
      {
        Debug.debugException(e);
        logCompletionMessage(true,
             ERR_LDIFMODIFY_WRITE_ERROR.get(
                  targetLDIF.getValue().getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }
    finally
    {
      if (ldifReader != null)
      {
        try
        {
          ldifReader.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
          logCompletionMessage(true,
               ERR_LDIFMODIFY_ERROR_CLOSING_READER.get(
                    sourceLDIF.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
        }
      }

      if (ldifWriter != null)
      {
        try
        {
          ldifWriter.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
          logCompletionMessage(true,
               ERR_LDIFMODIFY_ERROR_CLOSING_WRITER.get(
                    sourceLDIF.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
        }
      }
    }


    // If no entries were read and no updates were applied, then we'll consider
    // that an error, regardless of whether a read error was encountered.
    if ((entriesRead.get() == 0L) && (entriesUpdated.get() == 0L))
    {
      if (resultCode.get() == null)
      {
        logCompletionMessage(true,
             ERR_LDIFMODIFY_NO_SOURCE_ENTRIES.get(
                  sourceLDIF.getValue().getAbsolutePath()));
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        logCompletionMessage(true,
             ERR_LDIFMODIFY_COULD_NOT_READ_SOURCE_ENTRIES.get(
                  sourceLDIF.getValue().getAbsolutePath()));
        return resultCode.get();
      }
    }


    // If no entries were updated, then we'll also consider that an error.
    if ((entriesUpdated.get() == 0L) && (! changesIgnored))
    {
      logCompletionMessage(true,
           ERR_LDIFMODIFY_NO_CHANGES_APPLIED_WITH_ERRORS.get(
                changesLDIF.getValue().getAbsolutePath(),
                sourceLDIF.getValue().getAbsolutePath()));
      resultCode.compareAndSet(null, ResultCode.PARAM_ERROR);
      return resultCode.get();
    }


    // Create the final completion message that will be used.
    final long entriesNotUpdated =
         Math.max((entriesRead.get() - entriesUpdated.get()), 0);
    if (resultCode.get() == null)
    {
      logCompletionMessage(false,
           INFO_LDIFMODIFY_COMPLETED_SUCCESSFULLY.get(entriesRead.get(),
                entriesUpdated.get(), entriesNotUpdated));
      return ResultCode.SUCCESS;
    }
    else
    {
      logCompletionMessage(true,
           ERR_LDIFMODIFY_COMPLETED_WITH_ERRORS.get(entriesRead.get(),
                entriesUpdated.get(), entriesNotUpdated));
      return resultCode.get();
    }
  }



  /**
   * Reads all of the LDIF change records from the changes file into a list.
   *
   * @param  addAndSubsequentChangeRecords
   *              A map that will be updated with add change records for a given
   *              entry, along with any subsequent change records that apply to
   *              the entry after it has been added.  It must not be
   *              {@code null}, must be empty, and must be updatable.
   * @param  deletedEntryDNs
   *              A map that will be updated with the DNs of any entries that
   *              are targeted by delete modifications and that have not been
   *              previously added or renamed.  It must not be {@code null},
   *              must be empty, and must be updatable.
   * @param  modifyChangeRecords
   *              A map that will be updated with any modify change records
   *              that target an entry that has not been targeted by any other
   *              type of change.  It must not be {@code null}, must be empty,
   *              and must be updatable.
   * @param  modifyDNAndSubsequentChangeRecords
   *              A map that will be updated with any change records for modify
   *              DN operations that target a given entry, and any subsequent
   *              operations that target the entry with its new DN.  It must not
   *              be {@code null}, must be empty, and must be updatable.
   * @param  resultCode
   *              A reference to the final result code that should be used for
   *              the tool.  This may be updated if an error occurred during
   *              processing and no value is already set.  It must not be
   *              {@code null}, but is allowed to have no value assigned.
   *
   * @throws  LDAPException  If an unrecoverable error occurs during processing.
   */
  private void readChangeRecords(
       @NotNull final Map<DN,List<LDIFChangeRecord>>
            addAndSubsequentChangeRecords,
       @NotNull final Map<DN,Boolean> deletedEntryDNs,
       @NotNull final Map<DN,List<LDIFModifyChangeRecord>> modifyChangeRecords,
       @NotNull final Map<DN,ObjectPair<DN,List<LDIFChangeRecord>>>
            modifyDNAndSubsequentChangeRecords,
       @NotNull final AtomicReference<ResultCode> resultCode)
       throws LDAPException
  {
    LDIFException firstRecoverableException = null;
    try (LDIFReader ldifReader = getLDIFReader(changesReader,
         changesLDIF.getValue(), changesEncryptionPassphraseFile.getValue()))
    {
changeRecordLoop:
      while (true)
      {
        // Read the next record from the changes file.
        final LDIFRecord ldifRecord;
        try
        {
          ldifRecord = ldifReader.readLDIFRecord();
        }
        catch (final LDIFException e)
        {
          Debug.debugException(e);

          if (e.mayContinueReading())
          {
            if (firstRecoverableException == null)
            {
              firstRecoverableException = e;
            }

            err();
            wrapErr(ERR_LDIFMODIFY_CANNOT_READ_RECORD_CAN_CONTINUE.get(
                 changesLDIF.getValue().getAbsolutePath(),
                 StaticUtils.getExceptionMessage(e)));
            resultCode.compareAndSet(null, ResultCode.DECODING_ERROR);
            continue changeRecordLoop;
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_LDIFMODIFY_CANNOT_READ_RECORD_CANNOT_CONTINUE.get(
                      changesLDIF.getValue().getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }

        if (ldifRecord == null)
        {
          break;
        }


        // Make sure that we can parse the DN for the change record.  If not,
        // then that's an error.
        final DN parsedDN;
        try
        {
          parsedDN = ldifRecord.getParsedDN();
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);

          err();
          wrapErr(ERR_LDIFMODIFY_CANNOT_PARSE_CHANGE_RECORD_DN.get(
               String.valueOf(ldifRecord),
               changesLDIF.getValue().getAbsolutePath(), e.getMessage()));
          resultCode.compareAndSet(null, e.getResultCode());
          continue changeRecordLoop;
        }


        // Get the LDIF record as a change record.  If the record is an entry
        // rather than a change record, then we'll treat it as an add change
        // record.
        final LDIFChangeRecord changeRecord;
        if (ldifRecord instanceof Entry)
        {
          changeRecord = new LDIFAddChangeRecord((Entry) ldifRecord);
        }
        else
        {
          changeRecord = (LDIFChangeRecord) ldifRecord;
        }


        // If the change record is for a modify DN, then make sure that we can
        // parse the new DN.
        final DN parsedNewDN;
        if (changeRecord.getChangeType() == ChangeType.MODIFY_DN)
        {
          try
          {
            parsedNewDN = ((LDIFModifyDNChangeRecord) changeRecord).getNewDN();
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);

            err();
            wrapErr(ERR_LDIFMODIFY_CANNOT_PARSE_NEW_DN.get(
                 String.valueOf(changeRecord),
                 changesLDIF.getValue().getAbsolutePath(), e.getMessage()));
            resultCode.compareAndSet(null, e.getResultCode());
            continue changeRecordLoop;
          }
        }
        else
        {
          parsedNewDN = parsedDN;
        }


        // Look at the change type and determine how to handle the operation.
        switch (changeRecord.getChangeType())
        {
          case ADD:
            // Make sure that we haven't already seen an add for an entry with
            // the same DN (unless that add was subsequently deleted).
            if (addAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_MULTIPLE_ADDS_FOR_DN.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
              continue changeRecordLoop;
            }

            // Make sure that there are no modifies targeting an entry with the
            // same DN.
            if (modifyChangeRecords.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_ADD_TARGETS_MODIFIED_ENTRY.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
              continue changeRecordLoop;
            }

            // Make sure that there aren't any modify DN operations that will
            // create an entry with the same or a subordinate DN.
            for (final Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>> e :
                 modifyDNAndSubsequentChangeRecords.entrySet())
            {
              final DN newDN = e.getValue().getFirst();
              if (parsedDN.isAncestorOf(newDN, true))
              {
                err();
                wrapErr(ERR_LDIFMODIFY_ADD_CONFLICTS_WITH_MOD_DN.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString(), e.getKey().toString(),
                     newDN.toString()));
                resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
                continue changeRecordLoop;
              }
            }

            final List<LDIFChangeRecord> addList = new ArrayList<>();
            addList.add(changeRecord);
            addAndSubsequentChangeRecords.put(parsedDN, addList);
            break;


          case DELETE:
            // If the set of changes already included an add for this entry,
            // then remove that add and any subsequent changes for it.  This
            // isn't an error, so we don't need to set a result code.
            if (addAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              addAndSubsequentChangeRecords.remove(parsedDN);
              err();
              wrapErr(WARN_LDIFMODIFY_DELETE_OF_PREVIOUS_ADD.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify DN that targeted
            // the entry, then reject the change.
            if (modifyDNAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              final DN newDN =
                   modifyDNAndSubsequentChangeRecords.get(parsedDN).getFirst();

              err();
              wrapErr(ERR_LDIFMODIFY_DELETE_OF_PREVIOUS_RENAME.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString(), newDN.toString()));
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify DN whose new DN
            // equals or is subordinate to the DN for the delete change
            // record, then remove that modify DN operation and any subsequent
            // changes for it, and instead add a delete for the original DN.
            // This isn't an error, so we don't need to set a result code.
            final Iterator<Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>>>
                 deleteModDNIterator =
                 modifyDNAndSubsequentChangeRecords.entrySet().iterator();
            while (deleteModDNIterator.hasNext())
            {
              final Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>> e =
                   deleteModDNIterator.next();
              final DN newDN = e.getValue().getFirst();
              if (parsedDN.isAncestorOf(newDN, true))
              {
                final DN originalDN = e.getKey();
                deleteModDNIterator.remove();
                deletedEntryDNs.put(originalDN, Boolean.FALSE);

                err();
                wrapErr(WARN_LDIFMODIFY_DELETE_OF_PREVIOUSLY_RENAMED.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString(), originalDN.toString(),
                     newDN.toString()));
                continue changeRecordLoop;
              }
            }

            // If the set of changes already included a delete for the same
            // DN, then reject the new change.
            if (deletedEntryDNs.containsKey(parsedDN))
            {
              if (! ignoreDuplicateDeletes.isPresent())
              {
                err();
                wrapErr(ERR_LDIFMODIFY_MULTIPLE_DELETES_FOR_DN.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString()));
                resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              }
              continue changeRecordLoop;
            }

            // If the set of changes included any modifications for the same DN,
            // then remove those modifications.  This isn't an error, so we
            // don't need to set a result code.
            if (modifyChangeRecords.containsKey(parsedDN))
            {
              modifyChangeRecords.remove(parsedDN);
              err();
              wrapErr(WARN_LDIFMODIFY_DELETE_OF_PREVIOUSLY_MODIFIED.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
            }

            deletedEntryDNs.put(parsedDN, Boolean.FALSE);
            break;


          case MODIFY:
            // If the set of changes already included an add for an entry with
            // the same DN, then add the modify change record to the set of
            // changes following that add.
            if (addAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              addAndSubsequentChangeRecords.get(parsedDN).add(changeRecord);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify DN for an entry
            // with the same DN, then reject the new change.
            if (modifyDNAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              final DN newDN =
                   modifyDNAndSubsequentChangeRecords.get(parsedDN).getFirst();

              err();
              wrapErr(ERR_LDIFMODIFY_MODIFY_OF_RENAMED_ENTRY.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString(), newDN.toString()));
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify DN that would
            // result in an entry with the same DN as the modify, then add
            // the modify change record to the modify DN record's change list.
            for (final Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>> e :
                 modifyDNAndSubsequentChangeRecords.entrySet())
            {
              if (parsedDN.equals(e.getValue().getFirst()))
              {
                e.getValue().getSecond().add(changeRecord);
                continue changeRecordLoop;
              }
            }

            // If the set of changes already included a delete for an entry with
            // the same DN, then reject the new change.
            if (deletedEntryDNs.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_MODIFY_OF_DELETED_ENTRY.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify for an entry with
            // the same DN, then add the new change to that list.
            if (modifyChangeRecords.containsKey(parsedDN))
            {
              modifyChangeRecords.get(parsedDN).add(
                   (LDIFModifyChangeRecord) changeRecord);
              continue changeRecordLoop;
            }

            // Start a new change record list for the modify operation.
            final List<LDIFModifyChangeRecord> modList = new ArrayList<>();
            modList.add((LDIFModifyChangeRecord) changeRecord);
            modifyChangeRecords.put(parsedDN, modList);
            break;


          case MODIFY_DN:
            // If the set of changes already included an add for an entry with
            // the same DN, then reject the modify DN.
            if (addAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_MOD_DN_OF_ADDED_ENTRY.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.UNWILLING_TO_PERFORM);
              continue changeRecordLoop;
            }

            // If the set of changes already included an add for an entry with
            // an entry at or below the new DN, then reject the modify DN.
            for (final DN addedDN : addAndSubsequentChangeRecords.keySet())
            {
              if (addedDN.isDescendantOf(parsedNewDN, true))
              {
                err();
                wrapErr(ERR_LDIFMODIFY_MOD_DN_NEW_DN_CONFLICTS_WITH_ADD.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString(), parsedNewDN.toString(),
                     addedDN.toString()));
                resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
                continue changeRecordLoop;
              }
            }

            // If the set of changes already included a modify DN for an entry
            // with the same DN, then reject the modify DN.
            if (modifyDNAndSubsequentChangeRecords.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_MULTIPLE_MOD_DN_WITH_DN.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify DN for an entry
            // that set a new DN that matches the DN of the new record, then
            // reject the modify DN.
            for (final Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>> e :
                 modifyDNAndSubsequentChangeRecords.entrySet())
            {
              final DN newDN = e.getValue().getFirst();
              if (newDN.isDescendantOf(parsedDN, true))
              {
                err();
                wrapErr(
                     ERR_LDIFMODIFY_UNWILLING_TO_MODIFY_DN_MULTIPLE_TIMES.get(
                          changesLDIF.getValue().getAbsolutePath(),
                          parsedDN.toString(), parsedNewDN.toString(),
                          e.getKey().toString()));
                resultCode.compareAndSet(null, ResultCode.UNWILLING_TO_PERFORM);
                continue changeRecordLoop;
              }
            }

            // If the set of changes already included a modify DN that set a
            // new DN that is at or below the new DN, then reject the modify DN.
            for (final Map.Entry<DN,ObjectPair<DN,List<LDIFChangeRecord>>> e :
                 modifyDNAndSubsequentChangeRecords.entrySet())
            {
              final DN newDN = e.getValue().getFirst();
              if (newDN.isDescendantOf(parsedNewDN, true))
              {
                err();
                wrapErr(ERR_LDIFMODIFY_MOD_DN_CONFLICTS_WITH_MOD_DN.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString(), parsedNewDN.toString(),
                     e.getKey().toString(), newDN.toString()));
                resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
                continue changeRecordLoop;
              }
            }

            // If the set of changes already included a delete for an entry with
            //t he same DN, then reject the modify DN.
            if (deletedEntryDNs.containsKey(parsedDN))
            {
              err();
              wrapErr(ERR_LDIFMODIFY_MOD_DN_OF_DELETED_ENTRY.get(
                   changesLDIF.getValue().getAbsolutePath(),
                   parsedDN.toString()));
              resultCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
              continue changeRecordLoop;
            }

            // If the set of changes already included a modify for an entry that
            // is at or below the new DN, then reject the modify DN.
            for (final DN dn : modifyChangeRecords.keySet())
            {
              if (dn.isDescendantOf(parsedNewDN, true))
              {
                err();
                wrapErr(ERR_LDIFMODIFY_MOD_DN_NEW_DN_CONFLICTS_WITH_MOD.get(
                     changesLDIF.getValue().getAbsolutePath(),
                     parsedDN.toString(), parsedNewDN.toString(),
                     dn.toString()));
                resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
                continue changeRecordLoop;
              }
            }

            final List<LDIFChangeRecord> modDNList = new ArrayList<>();
            modDNList.add(changeRecord);
            modifyDNAndSubsequentChangeRecords.put(parsedDN,
                 new ObjectPair<DN,List<LDIFChangeRecord>>(parsedNewDN,
                      modDNList));
            break;
        }
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(e.getResultCode(),
           ERR_LDIFMODIFY_ERROR_OPENING_CHANGES_FILE.get(
                changesLDIF.getValue().getAbsolutePath(), e.getMessage()),
           e);
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDIFMODIFY_ERROR_READING_CHANGES_FILE.get(
                changesLDIF.getValue().getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (addAndSubsequentChangeRecords.isEmpty() && deletedEntryDNs.isEmpty() &&
         modifyChangeRecords.isEmpty() &&
         modifyDNAndSubsequentChangeRecords.isEmpty())
    {
      if (firstRecoverableException == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDIFMODIFY_NO_CHANGES.get(
                  changesLDIF.getValue().getAbsolutePath()));
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDIFMODIFY_NO_CHANGES_WITH_ERROR.get(
                  changesLDIF.getValue().getAbsolutePath()),
             firstRecoverableException);
      }
    }
  }



  /**
   * Retrieves an LDIF reader that may be used to read LDIF records (either
   * entries or change records) from the specified LDIF file.
   *
   * @param  existingReader  An LDIF reader that was already provided to the
   *                         tool for this purpose.  It may be {@code null} if
   *                         the LDIF reader should be created with the given
   *                         LDIF file and passphrase file.
   * @param  ldifFile        The LDIF file for which to create the reader.  It
   *                         may be {@code null} only if {@code existingReader}
   *                         is non-{@code null}.
   * @param  passphraseFile  The file containing the encryption passphrase
   *                         needed to decrypt the contents of the provided LDIF
   *                         file.  It may be {@code null} if the LDIF file is
   *                         not encrypted or if the user should be
   *                         interactively prompted for the passphrase.
   *
   * @return  The LDIF reader that was created.
   *
   * @throws  LDAPException  If a problem occurs while creating the LDIF reader.
   */
  @NotNull()
  private LDIFReader getLDIFReader(@Nullable final LDIFReader existingReader,
                                   @Nullable final File ldifFile,
                                   @Nullable final File passphraseFile)
          throws LDAPException
  {
    if (existingReader != null)
    {
      return existingReader;
    }

    if (passphraseFile != null)
    {
      readPassphraseFile(passphraseFile);
    }


    boolean closeStream = true;
    InputStream inputStream = null;
    try
    {
      inputStream = new FileInputStream(ldifFile);

      final ObjectPair<InputStream,char[]> p =
           ToolUtils.getPossiblyPassphraseEncryptedInputStream(
                inputStream, inputEncryptionPassphrases,
                (passphraseFile != null),
                INFO_LDIFMODIFY_ENTER_INPUT_ENCRYPTION_PW.get(
                     ldifFile.getName()),
                ERR_LDIFMODIFY_WRONG_ENCRYPTION_PW.get(), getOut(), getErr());
      inputStream = p.getFirst();
      addPassphrase(p.getSecond());

      inputStream = ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);

      final LDIFReader ldifReader = new LDIFReader(inputStream);
      if (stripTrailingSpaces.isPresent())
      {
        ldifReader.setTrailingSpaceBehavior(TrailingSpaceBehavior.STRIP);
      }
      else
      {
        ldifReader.setTrailingSpaceBehavior(TrailingSpaceBehavior.REJECT);
      }

      ldifReader.setSchema(Schema.getDefaultStandardSchema());

      closeStream = false;
      return ldifReader;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDIFMODIFY_ERROR_OPENING_INPUT_FILE.get(
                ldifFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if ((inputStream != null) && closeStream)
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
   * Reads the contents of the specified passphrase file and adds it to the list
   * of passphrases.
   *
   * @param  f  The passphrase file to read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the passphrase from the provided file.
   */
  private void readPassphraseFile(@NotNull final File f)
          throws LDAPException
  {
    try
    {
      addPassphrase(getPasswordFileReader().readPassword(f));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDIFMODIFY_CANNOT_READ_PW_FILE.get(f.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
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

    for (final char[] existingPassphrase : inputEncryptionPassphrases)
    {
      if (Arrays.equals(existingPassphrase, passphrase))
      {
        return;
      }
    }

    inputEncryptionPassphrases.add(passphrase);
  }



  /**
   * Creates the LDIF writer to use to write the output.
   *
   * @param  existingWriter  An LDIF writer that was already provided to the
   *                         tool for this purpose.  It may be {@code null} if
   *                         the LDIF writer should be created using the
   *                         provided arguments.
   *
   * @return  The LDIF writer that was created.
   *
   * @throws  LDAPException  If a problem occurs while creating the LDIF writer.
   */
  @NotNull()
  private LDIFWriter getLDIFWriter(@Nullable final LDIFWriter existingWriter)
          throws LDAPException
  {
    if (existingWriter != null)
    {
      return existingWriter;
    }

    final File outputFile = targetLDIF.getValue();
    final File passphraseFile = targetEncryptionPassphraseFile.getValue();


    OutputStream outputStream = null;
    boolean closeOutputStream = true;
    try
    {
      try
      {

        outputStream = new FileOutputStream(targetLDIF.getValue());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIFMODIFY_CANNOT_OPEN_OUTPUT_FILE.get(
                  outputFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      if (encryptTarget.isPresent())
      {
        try
        {
          final char[] passphrase;
          if (passphraseFile != null)
          {
            passphrase = getPasswordFileReader().readPassword(passphraseFile);
          }
          else
          {
            passphrase = ToolUtils.promptForEncryptionPassphrase(false, true,
                 INFO_LDIFMODIFY_ENTER_OUTPUT_ENCRYPTION_PW.get(),
                 INFO_LDIFMODIFY_CONFIRM_OUTPUT_ENCRYPTION_PW.get(), getOut(),
                 getErr()).toCharArray();
          }

          outputStream = new PassphraseEncryptedOutputStream(passphrase,
               outputStream, null, true, true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDIFMODIFY_CANNOT_ENCRYPT_OUTPUT_FILE.get(
                    outputFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      if (compressTarget.isPresent())
      {
        try
        {
          outputStream = new GZIPOutputStream(outputStream);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDIFMODIFY_CANNOT_COMPRESS_OUTPUT_FILE.get(
                    outputFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      final LDIFWriter ldifWriter = new LDIFWriter(outputStream);
      if (doNotWrap.isPresent())
      {
        ldifWriter.setWrapColumn(0);
      }
      else if (wrapColumn.isPresent())
      {
        ldifWriter.setWrapColumn(wrapColumn.getValue());
      }
      else
      {
        ldifWriter.setWrapColumn(WRAP_COLUMN);
      }

      closeOutputStream = false;
      return ldifWriter;
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
   * Updates the provided entry with any appropriate changes.
   *
   * @param  entry
   *              The entry to be processed.  It must not be {@code null}.
   * @param  addAndSubsequentChangeRecords
   *              A map that will be updated with add change records for a given
   *              entry, along with any subsequent change records that apply to
   *              the entry after it has been added.  It must not be
   *              {@code null}, must be empty, and must be updatable.
   * @param  deletedEntryDNs
   *              A map that will be updated with the DNs of any entries that
   *              are targeted by delete modifications and that have not been
   *              previously added or renamed.  It must not be {@code null},
   *              must be empty, and must be updatable.
   * @param  modifyChangeRecords
   *              A map that will be updated with any modify change records
   *              that target an entry that has not been targeted by any other
   *              type of change.  It must not be {@code null}, must be empty,
   *              and must be updatable.
   * @param  modifyDNAndSubsequentChangeRecords
   *              A map that will be updated with any change records for modify
   *              DN operations that target a given entry, and any subsequent
   *              operations that target the entry with its new DN.  It must not
   *              be {@code null}, must be empty, and must be updatable.
   * @param  comment
   *              A buffer that should be updated with any comment to be
   *              included in the output, even if the entry is not altered.  It
   *              must not be {@code null}, but it should be empty.
   * @param  resultCode
   *              A reference to the final result code that should be used for
   *              the tool.  This may be updated if an error occurred during
   *              processing and no value is already set.  It must not be
   *              {@code null}, but is allowed to have no value assigned.
   * @param  entriesUpdated
   *              A counter that should be incremented if any changes are
   *              applied (including deleting the entry).  It should  not be
   *              updated if none of the changes are applicable to the provided
   *              entry.  It must not be {@code null}.
   *
   * @return  The provided entry if none of the changes are applicable, an
   *          updated entry if changes are applied, or {@code null} if the entry
   *          should be deleted and therefore omitted from the target LDIF file.
   */
  @Nullable()
  private Entry updateEntry(@NotNull final Entry entry,
       @NotNull final Map<DN,List<LDIFChangeRecord>>
            addAndSubsequentChangeRecords,
       @NotNull final Map<DN,Boolean> deletedEntryDNs,
       @NotNull final Map<DN,List<LDIFModifyChangeRecord>> modifyChangeRecords,
       @NotNull final Map<DN,ObjectPair<DN,List<LDIFChangeRecord>>>
            modifyDNAndSubsequentChangeRecords,
       @NotNull final StringBuilder comment,
       @NotNull final AtomicReference<ResultCode> resultCode,
       @NotNull final AtomicLong entriesUpdated)
  {
    // Get the parsed DN for the entry.  If that fails, then we'll just return
    // the provided entry along with a comment explaining that its DN could not
    // be parsed.
    final DN entryDN;
    try
    {
      entryDN = entry.getParsedDN();

    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      resultCode.compareAndSet(null, e.getResultCode());
      appendComment(comment,
           ERR_LDIFMODIFY_CANNOT_PARSE_ENTRY_DN.get(e.getMessage()), true);
      return entry;
    }


    // See if there is a delete change record for the entry.  If so, then mark
    // the entry as deleted and return null.
    if (deletedEntryDNs.containsKey(entryDN))
    {
      deletedEntryDNs.put(entryDN, Boolean.TRUE);
      createChangeRecordComment(comment, INFO_LDIFMODIFY_APPLIED_DELETE.get(),
           entry, false);
      entriesUpdated.incrementAndGet();
      return null;
    }


    // See if there is a delete change record for one of the entry's superiors.
    // If so, then mark the entry as deleted and return null.
    DN parentDN = entryDN.getParent();
    while (parentDN != null)
    {
      if (deletedEntryDNs.containsKey(parentDN))
      {
        createChangeRecordComment(comment,
             INFO_LDIFMODIFY_APPLIED_DELETE_OF_ANCESTOR.get(
                  parentDN.toString()),
             entry, false);
        entriesUpdated.incrementAndGet();
        return null;
      }

      parentDN = parentDN.getParent();
    }


    // See if there are any modify change records that target the entry.  If so,
    // then apply those modifications.
    Entry updatedEntry = entry;
    final AtomicBoolean isUpdated = new AtomicBoolean(false);
    final List<String> errors = new ArrayList<>();
    final List<LDIFModifyChangeRecord> modRecords =
         modifyChangeRecords.remove(entryDN);
    if (modRecords != null)
    {
      for (final LDIFModifyChangeRecord r : modRecords)
      {
        updatedEntry = applyModification(updatedEntry, r, isUpdated, resultCode,
             comment);
      }
    }


    // See if the entry was targeted by a modify DN operation.  If so, then
    // rename the entry and see if there are any follow-on modifications.
    final ObjectPair<DN,List<LDIFChangeRecord>> modDNRecords =
         modifyDNAndSubsequentChangeRecords.remove(entryDN);
    if (modDNRecords != null)
    {
      for (final LDIFChangeRecord r : modDNRecords.getSecond())
      {
        if (r instanceof LDIFModifyDNChangeRecord)
        {
          final LDIFModifyDNChangeRecord modDNChangeRecord =
               (LDIFModifyDNChangeRecord) r;
          updatedEntry = applyModifyDN(updatedEntry, entryDN,
               modDNRecords.getFirst(), modDNChangeRecord.deleteOldRDN());
          createChangeRecordComment(comment,
               INFO_LDIFMODIFY_APPLIED_MODIFY_DN.get(), r, false);
          isUpdated.set(true);
        }
        else
        {
          updatedEntry = applyModification(updatedEntry,
               (LDIFModifyChangeRecord) r, isUpdated, resultCode, comment);
        }
      }
    }


    // See if there is an add change record that targets the same entry.  If so,
    // then the add won't be processed but maybe subsequent changes will be.
    final List<LDIFChangeRecord> addAndMods =
         addAndSubsequentChangeRecords.remove(entryDN);
    if (addAndMods != null)
    {
      for (final LDIFChangeRecord r : addAndMods)
      {
        if (r instanceof LDIFAddChangeRecord)
        {
          resultCode.compareAndSet(null, ResultCode.ENTRY_ALREADY_EXISTS);
          createChangeRecordComment(comment,
               ERR_LDIFMODIFY_NOT_ADDING_EXISTING_ENTRY.get(), r, true);
        }
        else
        {
          updatedEntry = applyModification(updatedEntry,
               (LDIFModifyChangeRecord) r, isUpdated, resultCode, comment);
        }
      }
    }


    if (isUpdated.get())
    {
      entriesUpdated.incrementAndGet();
    }
    else
    {
      if (comment.length() > 0)
      {
        appendComment(comment, StaticUtils.EOL, false);
        appendComment(comment, StaticUtils.EOL, false);
      }
      appendComment(comment, INFO_LDIFMODIFY_ENTRY_NOT_UPDATED.get(), false);
    }

    return updatedEntry;
  }



  /**
   * Creates a copy of the provided entry with the given modification applied.
   *
   * @param  entry               The entry to be updated.  It must not be
   *                             {@code null}.
   * @param  modifyChangeRecord  The modify change record to apply.  It must not
   *                             be {@code null}.
   * @param  isUpdated           A value that should be updated if the entry is
   *                             successfully modified.  It must not be
   *                             {@code null}.
   * @param  resultCode          A reference to the final result code that
   *                             should be used for the tool.  This may be
   *                             updated if an error occurred during processing
   *                             and no value is already set.  It must not be
   *                             {@code null}, but is allowed to have no value
   *                             assigned.
   * @param  comment             A buffer that should be updated with any
   *                             comment to be included in the output, even if
   *                             the entry is not altered.  It must not be
   *                             {@code null}, but it may be empty.
   *
   * @return  The entry with the modifications applied, or the original entry if
   *          an error occurred while applying the change.
   */
  @NotNull()
  private Entry applyModification(@NotNull final Entry entry,
                     @NotNull final LDIFModifyChangeRecord modifyChangeRecord,
                     @NotNull final AtomicBoolean isUpdated,
                     @NotNull final AtomicReference<ResultCode> resultCode,
                     @NotNull final StringBuilder comment)
  {
    try
    {
      final Entry updatedEntry = Entry.applyModifications(entry,
           (! strictModifications.isPresent()),
           modifyChangeRecord.getModifications());
      createChangeRecordComment(comment, INFO_LDIFMODIFY_APPLIED_MODIFY.get(),
           modifyChangeRecord, false);
      isUpdated.set(true);
      return updatedEntry;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      resultCode.compareAndSet(null, e.getResultCode());
      createChangeRecordComment(comment,
           ERR_LDIFMODIFY_ERROR_APPLYING_MODIFY.get(
                String.valueOf(e.getResultCode()), e.getMessage()),
           modifyChangeRecord, true);
      return entry;
    }
  }



  /**
   * Creates a copy of the provided entry with the given new DN.
   *
   * @param  entry         The entry to be renamed.  It must not be
   *                       {@code null}.
   * @param  originalDN    A parsed representation of the original DN for the
   *                       entry.  It must not be {@code null}.
   * @param  newDN         A parsed representation of the new DN for the entry.
   *                       It must not be {@code null}.
   * @param  deleteOldRDN  Indicates whether the old RDN values should be
   *                       removed from the entry.
   *
   * @return  The updated entry with the new DN and any other associated
   *          changes.
   */
  @NotNull()
  private Entry applyModifyDN(@NotNull final Entry entry,
                              @NotNull final DN originalDN,
                              @NotNull final DN newDN,
                              final boolean deleteOldRDN)
  {
    final Entry copy = entry.duplicate();
    copy.setDN(newDN);

    final RDN oldRDN = originalDN.getRDN();
    if (deleteOldRDN && (oldRDN != null))
    {
      for (final Attribute a : oldRDN.getAttributes())
      {
        for (final byte[] value : a.getValueByteArrays())
        {
          copy.removeAttributeValue(a.getName(), value);
        }
      }
    }

    final RDN newRDN = newDN.getRDN();
    if (newRDN != null)
    {
      for (final Attribute a : newRDN.getAttributes())
      {
        for (final byte[] value : a.getValueByteArrays())
        {
          copy.addAttribute(a);
        }
      }
    }

    return copy;
  }



  /**
   * Writes the provided LDIF record to the LDIF writer.
   *
   * @param  ldifWriter  The writer to which the LDIF record should be written.
   *                     It must not be {@code null}.
   * @param  ldifRecord  The LDIF record to be written.  It must not be
   *                     {@code null}.
   * @param  comment     The comment to include as part of the LDIF record.  It
   *                     may be {@code null} or empty if no comment should be
   *                     included.
   *
   * @throws  IOException  If an error occurs while attempting to write to the
   *                       LDIF writer.
   */
  private void writeLDIFRecord(@NotNull final LDIFWriter ldifWriter,
                               @NotNull final LDIFRecord ldifRecord,
                               @Nullable final CharSequence comment)
          throws IOException
  {
    if (suppressComments.isPresent() || (comment == null) ||
         (comment.length() == 0))
    {
      ldifWriter.writeLDIFRecord(ldifRecord);
    }
    else
    {
      ldifWriter.writeLDIFRecord(ldifRecord, comment.toString());
    }
  }



  /**
   * Appends the provided comment to the given buffer.
   *
   * @param  buffer   The buffer to which the comment should be appended.
   * @param  comment  The comment to be appended.
   * @param  isError  Indicates whether the comment represents an error that
   *                  should be added to the error list if it exists.  It should
   *                  be {@code false} if the comment is not an error, or if it
   *                  is an error but should not be added to the list of error
   *                  messages (e.g., because a message will be added through
   *                  some other means).
   */
  private void appendComment(@NotNull final StringBuilder buffer,
                             @NotNull final String comment,
                             final boolean isError)
  {
    buffer.append(comment);
    if (isError && (errorMessages != null))
    {
      errorMessages.add(comment);
    }
  }



  /**
   * Writes the provided comment to the LDIF writer.
   *
   * @param  ldifWriter  The writer to which the comment should be written.  It
   *                     must not be {@code null}.
   * @param  comment     The comment to be written.  It may be {@code null} or
   *                     empty if no comment should actually be written.
   * @param  isError     Indicates whether the comment represents an error that
   *                     should be added to the error list if it exists.  It
   *                     should be {@code false} if the comment is not an error,
   *                     or if it is an error but should not be added to the
   *                     list of error messages (e.g., because a message will be
   *                     added through some other means).
   *
   * @throws  IOException  If an error occurs while attempting to write to the
   *                       LDIF writer.
   */
  private void writeLDIFComment(@NotNull final LDIFWriter ldifWriter,
                                @Nullable final CharSequence comment,
                                final boolean isError)
          throws IOException
  {
    if (! (suppressComments.isPresent() || (comment == null) ||
         (comment.length() == 0)))
    {
      ldifWriter.writeComment(comment.toString(), false, true);
    }

    if (isError && (errorMessages != null) && (comment != null))
    {
      errorMessages.add(comment.toString());
    }
  }



  /**
   * Appends a comment to the provided buffer for the given LDIF record.
   *
   * @param  buffer   The buffer to which the comment should be appended.  It
   *                  must not be {@code null}.
   * @param  message  The message to include before the LDIF record.  It must
   *                  not be {@code null}.
   * @param  record   The LDIF record to include in the comment.
   * @param  isError  Indicates whether the comment represents an error that
   *                  should be added to the error list if it exists.  It should
   *                  be {@code false} if the comment is not an error, or if it
   *                  is an error but should not be added to the list of error
   *                  messages (e.g., because a message will be added through
   *                  some other means).
   */
  private void createChangeRecordComment(@NotNull final StringBuilder buffer,
                                         @NotNull final String message,
                                         @NotNull final LDIFRecord record,
                                         final boolean isError)
  {
    final int initialLength = buffer.length();
    if (initialLength > 0)
    {
      buffer.append(StaticUtils.EOL);
      buffer.append(StaticUtils.EOL);
    }

    buffer.append(message);
    buffer.append(StaticUtils.EOL);

    final int wrapCol;
    if (wrapColumn.isPresent() && (wrapColumn.getValue() > 20) &&
         (wrapColumn.getValue() <= 85))
    {
      wrapCol = wrapColumn.getValue() - 10;
    }
    else
    {
      wrapCol = 75;
    }

    for (final String line : record.toLDIF(wrapCol))
    {
      buffer.append("     ");
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }

    if (isError && (errorMessages != null))
    {
      if (initialLength == 0)
      {
        errorMessages.add(buffer.toString());
      }
      else
      {
        errorMessages.add(buffer.toString().substring(initialLength));
      }
    }
  }



  /**
   * Writes a wrapped version of the provided message to standard error.  If an
   * {@code errorList} is also available, then the message will also be added to
   * that list.
   *
   * @param  message  The message to be written.  It must not be {@code null].
   */
  private void wrapErr(@NotNull final String message)
  {
    wrapErr(0, WRAP_COLUMN, message);
    if (errorMessages != null)
    {
      errorMessages.add(message);
    }
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
      wrapErr(message);
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
           "--sourceLDIF", "original.ldif",
           "--changesLDIF", "changes.ldif",
           "--targetLDIF", "updated.ldif"
         },
         INFO_LDIFMODIFY_EXAMPLE.get("changes.ldif", "original.ldif",
              "updated.ldif"));

    return examples;
  }
}
