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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.listener.SearchEntryParer;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.EntryValidator;
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
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;

import static com.unboundid.ldif.LDIFMessages.*;



/**
 * This class provides a command-line tool that can be used to search for
 * entries matching a given set of criteria in an LDIF file.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDIFSearch
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



  // The argument parser for this tool.
  @Nullable private volatile ArgumentParser parser;

  // The completion message for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // Indicates whether the LDIF encryption passphrase file has been read.
  private volatile boolean ldifEncryptionPassphraseFileRead;

  // Encryption passphrases used thus far.
  @NotNull private final List<char[]> inputEncryptionPassphrases;

  // The list of LDAP URLs to use when processing searches, mapped to the
  // corresponding search entry parers.
  @NotNull private final List<LDAPURL> searchURLs;

  // The command-line arguments supported by this tool.
  @Nullable private BooleanArgument checkSchema;
  @Nullable private BooleanArgument compressOutput;
  @Nullable private BooleanArgument doNotWrap;
  @Nullable private BooleanArgument encryptOutput;
  @Nullable private BooleanArgument isCompressed;
  @Nullable private BooleanArgument overwriteExistingOutputFile;
  @Nullable private BooleanArgument separateOutputFilePerSearch;
  @Nullable private BooleanArgument stripTrailingSpaces;
  @Nullable private DNArgument baseDN;
  @Nullable private FileArgument filterFile;
  @Nullable private FileArgument ldapURLFile;
  @Nullable private FileArgument ldifEncryptionPassphraseFile;
  @Nullable private FileArgument ldifFile;
  @Nullable private FileArgument outputFile;
  @Nullable private FileArgument outputEncryptionPassphraseFile;
  @Nullable private FileArgument schemaPath;
  @Nullable private IntegerArgument sizeLimit;
  @Nullable private IntegerArgument timeLimitSeconds;
  @Nullable private IntegerArgument wrapColumn;
  @Nullable private ScopeArgument scope;



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
    final LDIFSearch tool = new LDIFSearch(out, err);
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
  public LDIFSearch(@Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    super(out, err);

    parser = null;
    completionMessage = new AtomicReference<>();
    inputEncryptionPassphrases = new ArrayList<>(5);
    searchURLs = new ArrayList<>();
    ldifEncryptionPassphraseFileRead = false;

    checkSchema = null;
    compressOutput = null;
    doNotWrap = null;
    encryptOutput = null;
    isCompressed = null;
    overwriteExistingOutputFile = null;
    separateOutputFilePerSearch = null;
    stripTrailingSpaces = null;
    baseDN = null;
    filterFile = null;
    ldapURLFile = null;
    ldifEncryptionPassphraseFile = null;
    ldifFile = null;
    outputFile = null;
    outputEncryptionPassphraseFile = null;
    schemaPath = null;
    sizeLimit = null;
    timeLimitSeconds = null;
    wrapColumn = null;
    scope = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldifsearch";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDIFSEARCH_TOOL_DESCRIPTION.get();
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
    return -1;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return INFO_LDIFSEARCH_TRAILING_ARGS_PLACEHOLDER.get();
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
    this.parser = parser;


    ldifFile = new FileArgument('l', "ldifFile", true, 0, null,
         INFO_LDIFSEARCH_ARG_DESC_LDIF_FILE.get(), true, true, true, false);
    ldifFile.addLongIdentifier("ldif-file", true);
    ldifFile.addLongIdentifier("inputFile", true);
    ldifFile.addLongIdentifier("input-file", true);
    ldifFile.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    parser.addArgument(ldifFile);


    final String ldifPWDesc;
    if (PING_SERVER_AVAILABLE)
    {
      ldifPWDesc = INFO_LDIFSEARCH_ARG_DESC_LDIF_PW_FILE_PING_SERVER.get();
    }
    else
    {
      ldifPWDesc = INFO_LDIFSEARCH_ARG_DESC_LDIF_PW_FILE_STANDALONE.get();
    }
    ldifEncryptionPassphraseFile = new FileArgument(null,
         "ldifEncryptionPassphraseFile", false, 1, null, ldifPWDesc, true,
         true, true, false);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "ldif-encryption-passphrase-file", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("ldifPassphraseFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("ldif-passphrase-file",
         true);
    ldifEncryptionPassphraseFile.addLongIdentifier("ldifEncryptionPasswordFile",
         true);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "ldif-encryption-password-file", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("ldifPasswordFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("ldif-password-file", true);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "inputEncryptionPassphraseFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "input-encryption-passphrase-file", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("inputPassphraseFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("input-passphrase-file",
         true);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "inputEncryptionPasswordFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier(
         "input-encryption-password-file", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("inputPasswordFile", true);
    ldifEncryptionPassphraseFile.addLongIdentifier("input-password-file", true);
    ldifEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    parser.addArgument(ldifEncryptionPassphraseFile);


    stripTrailingSpaces = new BooleanArgument(null, "stripTrailingSpaces", 1,
         INFO_LDIFSEARCH_ARG_DESC_STRIP_TRAILING_SPACES.get());
    stripTrailingSpaces.addLongIdentifier("strip-trailing-spaces", true);
    stripTrailingSpaces.addLongIdentifier("ignoreTrailingSpaces", true);
    stripTrailingSpaces.addLongIdentifier("ignore-trailing-spaces", true);
    stripTrailingSpaces.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    parser.addArgument(stripTrailingSpaces);


    final String schemaPathDesc;
    if (PING_SERVER_AVAILABLE)
    {
      schemaPathDesc = INFO_LDIFSEARCH_ARG_DESC_SCHEMA_PATH_PING_SERVER.get();
    }
    else
    {
      schemaPathDesc = INFO_LDIFSEARCH_ARG_DESC_SCHEMA_PATH_STANDALONE.get();
    }
    schemaPath = new FileArgument(null, "schemaPath", false, 0, null,
         schemaPathDesc, true, true, false, false);
    schemaPath.addLongIdentifier("schema-path", true);
    schemaPath.addLongIdentifier("schemaFile", true);
    schemaPath.addLongIdentifier("schema-file", true);
    schemaPath.addLongIdentifier("schemaDirectory", true);
    schemaPath.addLongIdentifier("schema-directory", true);
    schemaPath.addLongIdentifier("schema", true);
    schemaPath.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    parser.addArgument(schemaPath);


    checkSchema = new BooleanArgument(null, "checkSchema", 1,
         INFO_LDIFSEARCH_ARG_DESC_CHECK_SCHEMA.get());
    checkSchema.addLongIdentifier("check-schema", true);
    checkSchema.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    parser.addArgument(checkSchema);


    isCompressed = new BooleanArgument(null, "isCompressed", 1,
         INFO_LDIFSEARCH_ARG_DESC_IS_COMPRESSED.get());
    isCompressed.addLongIdentifier("is-compressed", true);
    isCompressed.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_INPUT.get());
    isCompressed.setHidden(true);
    parser.addArgument(isCompressed);


    outputFile = new FileArgument('o', "outputFile", false, 1, null,
         INFO_LDIFSEARCH_ARG_DESC_OUTPUT_FILE.get(), false, true, true, false);
    outputFile.addLongIdentifier("output-file", true);
    outputFile.addLongIdentifier("outputLDIF", true);
    outputFile.addLongIdentifier("output-ldif", true);
    outputFile.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputFile);


    separateOutputFilePerSearch = new BooleanArgument(null,
         "separateOutputFilePerSearch", 1,
         INFO_LDIFSEARCH_ARG_DESC_SEPARATE_OUTPUT_FILES.get());
    separateOutputFilePerSearch.addLongIdentifier(
         "separate-output-file-per-search", true);
    separateOutputFilePerSearch.addLongIdentifier("separateOutputFiles", true);
    separateOutputFilePerSearch.addLongIdentifier("separate-output-files",
         true);
    separateOutputFilePerSearch.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(separateOutputFilePerSearch);


    compressOutput = new BooleanArgument(null, "compressOutput", 1,
         INFO_LDIFSEARCH_ARG_DESC_COMPRESS_OUTPUT.get());
    compressOutput.addLongIdentifier("compress-output", true);
    compressOutput.addLongIdentifier("compressLDIF", true);
    compressOutput.addLongIdentifier("compress-ldif", true);
    compressOutput.addLongIdentifier("compress", true);
    compressOutput.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(compressOutput);


    encryptOutput = new BooleanArgument(null, "encryptOutput", 1,
         INFO_LDIFSEARCH_ARG_DESC_ENCRYPT_OUTPUT.get());
    encryptOutput.addLongIdentifier("encrypt-output", true);
    encryptOutput.addLongIdentifier("encryptLDIF", true);
    encryptOutput.addLongIdentifier("encrypt-ldif", true);
    encryptOutput.addLongIdentifier("encrypt", true);
    encryptOutput.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(encryptOutput);


    outputEncryptionPassphraseFile = new FileArgument(null,
         "outputEncryptionPassphraseFile", false, 1, null,
         INFO_LDIFSEARCH_ARG_DESC_OUTPUT_PW_FILE.get(), true, true, true,
         false);
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
    outputEncryptionPassphraseFile.addLongIdentifier(
         "outputEncryptionPasswordFile", true);
    outputEncryptionPassphraseFile.addLongIdentifier(
         "output-encryption-password-file", true);
    outputEncryptionPassphraseFile.addLongIdentifier("outputPasswordFile",
         true);
    outputEncryptionPassphraseFile.addLongIdentifier("output-password-file",
         true);
    outputEncryptionPassphraseFile.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputEncryptionPassphraseFile);


    overwriteExistingOutputFile = new BooleanArgument('O',
         "overwriteExistingOutputFile", 1,
         INFO_LDIFSEARCH_ARG_DESC_OVERWRITE_EXISTING.get());
    overwriteExistingOutputFile.addLongIdentifier(
         "overwrite-existing-output-file", true);
    overwriteExistingOutputFile.addLongIdentifier(
         "overwriteExistingOutputFiles", true);
    overwriteExistingOutputFile.addLongIdentifier(
         "overwrite-existing-output-files", true);
    overwriteExistingOutputFile.addLongIdentifier("overwriteExistingOutput",
         true);
    overwriteExistingOutputFile.addLongIdentifier("overwrite-existing-output",
         true);
    overwriteExistingOutputFile.addLongIdentifier("overwriteExisting", true);
    overwriteExistingOutputFile.addLongIdentifier("overwrite-existing", true);
    overwriteExistingOutputFile.addLongIdentifier("overwrite", true);
    overwriteExistingOutputFile.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(overwriteExistingOutputFile);


    wrapColumn = new IntegerArgument(null, "wrapColumn", false, 1, null,
         INFO_LDIFSEARCH_ARG_DESC_WRAP_COLUMN.get(), 5, Integer.MAX_VALUE);
    wrapColumn.addLongIdentifier("wrap-column", true);
    wrapColumn.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(wrapColumn);


    doNotWrap = new BooleanArgument('T', "doNotWrap", 1,
         INFO_LDIFSEARCH_ARG_DESC_DO_NOT_WRAP.get());
    doNotWrap.addLongIdentifier("do-not-wrap", true);
    doNotWrap.addLongIdentifier("dontWrap", true);
    doNotWrap.addLongIdentifier("dont-wrap", true);
    doNotWrap.addLongIdentifier("noWrap", true);
    doNotWrap.addLongIdentifier("no-wrap", true);
    doNotWrap.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_OUTPUT.get());
    parser.addArgument(doNotWrap);


    baseDN = new DNArgument('b', "baseDN", false, 1, null,
         INFO_LDIFSEARCH_ARG_DESC_BASE_DN.get());
    baseDN.addLongIdentifier("base-dn", true);
    baseDN.addLongIdentifier("searchBaseDN", true);
    baseDN.addLongIdentifier("search-base-dn", true);
    baseDN.addLongIdentifier("searchBase", true);
    baseDN.addLongIdentifier("search-base", true);
    baseDN.addLongIdentifier("base", true);
    baseDN.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    parser.addArgument(baseDN);


    scope = new ScopeArgument('s', "scope", false, null,
         INFO_LDIFSEARCH_ARG_DESC_SCOPE.get());
    scope.addLongIdentifier("searchScope", true);
    scope.addLongIdentifier("search-scope", true);
    scope.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    parser.addArgument(scope);


    filterFile = new FileArgument('f', "filterFile", false, 0, null,
         INFO_LDIFSEARCH_ARG_DESC_FILTER_FILE.get(), true, true, true, false);
    filterFile.addLongIdentifier("filter-file", true);
    filterFile.addLongIdentifier("filtersFile", true);
    filterFile.addLongIdentifier("filters-file", true);
    filterFile.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    parser.addArgument(filterFile);


    ldapURLFile = new FileArgument(null, "ldapURLFile", false, 0, null,
         INFO_LDIFSEARCH_ARG_DESC_LDAP_URL_FILE.get(), true, true, true, false);
    ldapURLFile.addLongIdentifier("ldap-url-file", true);
    ldapURLFile.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    parser.addArgument(ldapURLFile);


    sizeLimit = new IntegerArgument('z', "sizeLimit", false, 1, null,
         INFO_LDIFSEARCH_ARG_DESC_SIZE_LIMIT.get(), 0, Integer.MAX_VALUE, 0);
    sizeLimit.addLongIdentifier("size-limit", true);
    sizeLimit.addLongIdentifier("searchSizeLimit", true);
    sizeLimit.addLongIdentifier("search-size-limit", true);
    sizeLimit.setArgumentGroupName(INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    sizeLimit.setHidden(true);
    parser.addArgument(sizeLimit);


    timeLimitSeconds = new IntegerArgument('t', "timeLimitSeconds", false, 1,
         null, INFO_LDIFSEARCH_ARG_DESC_TIME_LIMIT_SECONDS.get(), 0,
         Integer.MAX_VALUE, 0);
    timeLimitSeconds.addLongIdentifier("time-limit-seconds", true);
    timeLimitSeconds.addLongIdentifier("timeLimit", true);
    timeLimitSeconds.setArgumentGroupName(
         INFO_LDIFSEARCH_ARG_GROUP_CRITERIA.get());
    timeLimitSeconds.setHidden(true);
    parser.addArgument(timeLimitSeconds);


    parser.addDependentArgumentSet(separateOutputFilePerSearch, outputFile);
    parser.addDependentArgumentSet(compressOutput, outputFile);
    parser.addDependentArgumentSet(encryptOutput, outputFile);
    parser.addDependentArgumentSet(overwriteExistingOutputFile, outputFile);
    parser.addDependentArgumentSet(outputEncryptionPassphraseFile,
         encryptOutput);

    parser.addExclusiveArgumentSet(wrapColumn, doNotWrap);
    parser.addExclusiveArgumentSet(baseDN, ldapURLFile);
    parser.addExclusiveArgumentSet(scope, ldapURLFile);
    parser.addExclusiveArgumentSet(filterFile, ldapURLFile);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If the output file exists and either compressOutput or encryptOutput is
    // present, then the overwrite argument must also be present.
    final File outFile = outputFile.getValue();
    if ((outFile != null) && outFile.exists() &&
         (compressOutput.isPresent() || encryptOutput.isPresent()) &&
         (! overwriteExistingOutputFile.isPresent()))
    {
      throw new ArgumentException(
           ERR_LDIFSEARCH_APPEND_WITH_COMPRESSION_OR_ENCRYPTION.get(
                compressOutput.getIdentifierString(),
                encryptOutput.getIdentifierString(),
                overwriteExistingOutputFile.getIdentifierString()));
    }


    // Create the set of LDAP URLs to use when issuing the searches.
    final List<String> trailingArgs = parser.getTrailingArguments();
    if (filterFile.isPresent())
    {
      // If there are trailing arguments, then make sure the first one is not a
      // valid filter.
      if (! trailingArgs.isEmpty())
      {
        try
        {
          Filter.create(trailingArgs.get(0));
          throw new ArgumentException(
               ERR_LDIFSEARCH_FILTER_FILE_WITH_TRAILING_FILTER.get());
        }
        catch (final LDAPException e)
        {
          // This was expected.
        }
      }

      readFilterFile();
    }
    else if (ldapURLFile.isPresent())
    {
      // Make sure there aren't any trailing arguments.
      if (! trailingArgs.isEmpty())
      {
        throw new ArgumentException(
             ERR_LDIFSEARCH_LDAP_URL_FILE_WITH_TRAILING_ARGS.get());
      }

      readLDAPURLFile();


      // If there are multiple LDAP URLs, and if they should not be sent to
      // separate output files, then they must all have the same set of
      // requested attributes.
      if ((searchURLs.size() > 1) &&
           (! separateOutputFilePerSearch.isPresent()))
      {
        final Iterator<LDAPURL> iterator = searchURLs.iterator();
        final Set<String> requestedAttrs =
             new HashSet<>(Arrays.asList(iterator.next().getAttributes()));
        while (iterator.hasNext())
        {
          final Set<String> attrSet = new HashSet<>(Arrays.asList(
               iterator.next().getAttributes()));
          if (! requestedAttrs.equals(attrSet))
          {
            throw new ArgumentException(
                 ERR_LDIFSEARCH_DIFFERENT_URL_ATTRS_IN_SAME_FILE.get(
                      ldapURLFile.getIdentifierString(),
                      separateOutputFilePerSearch.getIdentifierString()));
          }
        }
      }
    }
    else
    {
      // Make sure there is at least one trailing argument, and that it's a
      // valid filter.  If there are any others, then they must be the
      // requested arguments.
      if (trailingArgs.isEmpty())
      {
        throw new ArgumentException(ERR_LDIFSEARCH_NO_FILTER.get());
      }


      final Filter filter;
      final String[] requestedAttributes;
      try
      {
        final List<String> trailingArgList = new ArrayList<>(trailingArgs);
        filter = Filter.create(trailingArgList.remove(0));
        requestedAttributes = trailingArgList.toArray(StaticUtils.NO_STRINGS);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDIFSEARCH_FIRST_TRAILING_ARG_NOT_FILTER.get(), e);
      }


      DN dn = baseDN.getValue();
      if (dn == null)
      {
        dn = DN.NULL_DN;
      }

      SearchScope searchScope = scope.getValue();
      if (searchScope == null)
      {
        searchScope = SearchScope.SUB;
      }

      try
      {
        searchURLs.add(new LDAPURL("ldap", null, null, dn, requestedAttributes,
             searchScope, filter));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        // This should never happen.
        throw new ArgumentException(StaticUtils.getExceptionMessage(e), e);
      }
    }
  }



  /**
   * Uses the contents of any specified filter files, along with the configured
   * base DN, scope, and requested attributes, to populate the set of search
   * URLs.
   *
   * @throws  ArgumentException  If a problem is encountered while constructing
   *                             the search URLs.
   */
  private void readFilterFile()
          throws ArgumentException
  {
    DN dn = baseDN.getValue();
    if (dn == null)
    {
      dn = DN.NULL_DN;
    }

    SearchScope searchScope = scope.getValue();
    if (searchScope == null)
    {
      searchScope = SearchScope.SUB;
    }

    final String[] requestedAttributes =
         parser.getTrailingArguments().toArray(StaticUtils.NO_STRINGS);

    for (final File f : filterFile.getValues())
    {
      final InputStream inputStream;
      try
      {
        inputStream = openInputStream(f);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new ArgumentException(e.getMessage(), e);
      }

      try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(inputStream)))
      {
        while (true)
        {
          final String line = reader.readLine();
          if (line == null)
          {
            break;
          }

          if (line.isEmpty() || line.startsWith("#"))
          {
            continue;
          }

          try
          {
            final Filter filter = Filter.create(line.trim());
            searchURLs.add(new LDAPURL("ldap", null, null, dn,
                 requestedAttributes, searchScope, filter));
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);
            throw new ArgumentException(
                 ERR_LDIFSEARCH_FILTER_FILE_INVALID_FILTER.get(line,
                      f.getAbsolutePath(), e.getMessage()),
                 e);
          }
        }
      }
      catch (final IOException e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDIFSEARCH_ERROR_READING_FILTER_FILE.get(f.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
      finally
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

    if (searchURLs.isEmpty())
    {
      throw new ArgumentException(ERR_LDIFSEARCH_NO_FILTERS_FROM_FILE.get(
           filterFile.getValues().get(0).getAbsolutePath()));
    }
  }



  /**
   * Uses the contents of any specified LDAP URL files to populate the set of
   * search URLs.
   *
   * @throws  ArgumentException  If a problem is encountered while constructing
   *                             the search URLs.
   */
  private void readLDAPURLFile()
          throws ArgumentException
  {
    for (final File f : ldapURLFile.getValues())
    {
      final InputStream inputStream;
      try
      {
        inputStream = openInputStream(f);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new ArgumentException(e.getMessage(), e);
      }

      try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(inputStream)))
      {
        while (true)
        {
          final String line = reader.readLine();
          if (line == null)
          {
            break;
          }

          if (line.isEmpty() || line.startsWith("#"))
          {
            continue;
          }

          try
          {
            searchURLs.add(new LDAPURL(line.trim()));
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);
            throw new ArgumentException(
                 ERR_LDIFSEARCH_LDAP_URL_FILE_INVALID_URL.get(line,
                      f.getAbsolutePath(), e.getMessage()),
                 e);
          }
        }
      }
      catch (final IOException e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDIFSEARCH_ERROR_READING_LDAP_URL_FILE.get(f.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
      finally
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

    if (searchURLs.isEmpty())
    {
      throw new ArgumentException(ERR_LDIFSEARCH_NO_URLS_FROM_FILE.get(
           ldapURLFile.getValues().get(0).getAbsolutePath()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
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
           ERR_LDIFSEARCH_CANNOT_GET_SCHEMA.get(
                StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    // Create search entry parers for all of the search URLs.
    final Map<LDAPURL,SearchEntryParer> urlMap = new LinkedHashMap<>();
    for (final LDAPURL url : searchURLs)
    {
      final SearchEntryParer parer = new SearchEntryParer(
           Arrays.asList(url.getAttributes()), schema);
      urlMap.put(url, parer);
    }


    // If we should check schema, then create the entry validator.
    final EntryValidator entryValidator;
    if (checkSchema.isPresent())
    {
      entryValidator = new EntryValidator(schema);
    }
    else
    {
      entryValidator = null;
    }


    // Create the output files, if appropriate.
    boolean closewriter = true;
    LDIFWriter singleWriter = null;
    SearchEntryParer singleParer = null;
    final Map<LDAPURL,LDIFSearchSeparateSearchDetails> separateWriters =
         new LinkedHashMap<>();
    try
    {
      if (outputFile.isPresent())
      {
        final int numURLs = searchURLs.size();
        if (separateOutputFilePerSearch.isPresent() && (numURLs > 1))
        {
          int i=1;
          for (final LDAPURL url : searchURLs)
          {
            final File f = new
                 File(outputFile.getValue().getAbsolutePath() + '.' + i);
            final LDIFSearchSeparateSearchDetails details =
                 new LDIFSearchSeparateSearchDetails(url, f,
                      createLDIFWriter(f, url), schema);
            separateWriters.put(url, details);
            i++;
          }
        }
        else
        {
          singleWriter = createLDIFWriter(outputFile.getValue(), null);
        }
      }
      else
      {
        singleWriter = new LDIFWriter(getOut());
        closewriter = false;
      }


      // Iterate through the LDIF files and process the entries they contain.
      boolean errorEncountered = false;
      final List<LDAPURL> matchingURLs = new ArrayList<>();
      final List<String> entryInvalidReasons = new ArrayList<>();
      for (final File f : ldifFile.getValues())
      {
        final LDIFReader ldifReader;
        try
        {
          ldifReader = new LDIFReader(openInputStream(f));

          if (stripTrailingSpaces.isPresent())
          {
            ldifReader.setTrailingSpaceBehavior(TrailingSpaceBehavior.STRIP);
          }
          else
          {
            ldifReader.setTrailingSpaceBehavior(TrailingSpaceBehavior.REJECT);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_LDIFSEARCH_CANNOT_OPEN_LDIF_FILE.get(f.getName(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }

        try
        {
          while (true)
          {
            final Entry entry;
            try
            {
              entry = ldifReader.readEntry();
            }
            catch (final LDIFException e)
            {
              Debug.debugException(e);
              if (e.mayContinueReading())
              {
                commentToErr(ERR_LDIFSEARCH_RECOVERABLE_READ_ERROR.get(
                     f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
                errorEncountered = true;
                continue;
              }
              else
              {
                logCompletionMessage(true,
                     ERR_LDIFSEARCH_UNRECOVERABLE_READ_ERROR.get(
                          f.getAbsolutePath(),
                          StaticUtils.getExceptionMessage(e)));
                return ResultCode.LOCAL_ERROR;
              }
            }
            catch (final Exception e)
            {
              logCompletionMessage(true,
                   ERR_LDIFSEARCH_UNRECOVERABLE_READ_ERROR.get(
                        f.getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e)));
              return ResultCode.LOCAL_ERROR;
            }

            if (entry == null)
            {
              break;
            }

            if (entryValidator != null)
            {
              entryInvalidReasons.clear();
              if (! entryValidator.entryIsValid(entry, entryInvalidReasons))
              {
                commentToErr(ERR_LDIFSEARCH_ENTRY_VIOLATES_SCHEMA.get(
                     entry.getDN()));
                for (final String invalidReason : entryInvalidReasons)
                {
                  commentToErr("- " + invalidReason);
                }

                err();
                errorEncountered = true;
                continue;
              }
            }

            if (singleWriter != null)
            {
              matchingURLs.clear();
              for (final LDAPURL url : searchURLs)
              {
                if (urlMatchesEntry(url, entry))
                {
                  matchingURLs.add(url);
                }
              }

              if (matchingURLs.isEmpty())
              {
                continue;
              }

              try
              {
                if (searchURLs.size() > 1)
                {
                  singleWriter.writeComment(
                       INFO_LDIFSEARCH_ENTRY_MATCHES_URLS.get(entry.getDN()),
                       false, false);
                  for (final LDAPURL url : matchingURLs)
                  {
                    singleWriter.writeComment(url.toString(), false, false);
                  }
                }

                if (singleParer == null)
                {
                  singleParer = new SearchEntryParer(
                       Arrays.asList(searchURLs.get(0).getAttributes()),
                       schema);
                }

                final Entry paredEntry = singleParer.pareEntry(entry);
                singleWriter.writeEntry(paredEntry);

                if (! outputFile.isPresent())
                {
                  singleWriter.flush();
                }
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                if (outputFile.isPresent())
                {
                  logCompletionMessage(true,
                       ERR_LDIFSEARCH_WRITE_ERROR_WITH_FILE.get(entry.getDN(),
                            outputFile.getValue().getAbsolutePath(),
                            StaticUtils.getExceptionMessage(e)));
                }
                else
                {
                  logCompletionMessage(true,
                       ERR_LDIFSEARCH_WRITE_ERROR_NO_FILE.get(entry.getDN(),
                            StaticUtils.getExceptionMessage(e)));
                }
                return ResultCode.LOCAL_ERROR;
              }
            }
            else
            {
              for (final LDIFSearchSeparateSearchDetails details :
                   separateWriters.values())
              {
                final LDAPURL url = details.getLDAPURL();
                if (urlMatchesEntry(url, entry))
                {
                  try
                  {
                    final Entry paredEntry =
                         details.getSearchEntryParer().pareEntry(entry);
                    details.getLDIFWriter().writeEntry(paredEntry);
                  }
                  catch (final Exception ex)
                  {
                    Debug.debugException(ex);
                    logCompletionMessage(true,
                         ERR_LDIFSEARCH_WRITE_ERROR_WITH_FILE.get(entry.getDN(),
                              details.getOutputFile().getAbsolutePath(),
                              StaticUtils.getExceptionMessage(ex)));
                    return ResultCode.LOCAL_ERROR;
                  }
                }
              }
            }
          }
        }
        finally
        {
          try
          {
            ldifReader.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }

      if (errorEncountered)
      {
        logCompletionMessage(true,
             WARN_LDIFSEARCH_COMPLETED_WITH_ERRORS.get());
        return ResultCode.PARAM_ERROR;
      }
      else
      {
        logCompletionMessage(false,
             INFO_LDIFSEARCH_COMPLETED_SUCCESSFULLY.get());
        return ResultCode.SUCCESS;
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      return e.getResultCode();
    }
    finally
    {
      if (singleWriter != null)
      {
        try
        {
          singleWriter.flush();

          if (closewriter)
          {
            singleWriter.close();
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      for (final LDIFSearchSeparateSearchDetails details :
           separateWriters.values())
      {
        try
        {
          details.getLDIFWriter().close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
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
   * Opens the input stream to use to read from the specified file.
   *
   * @param  f  The file for which to open the input stream.  It may optionally
   *            be compressed and/or encrypted.
   *
   * @return  The input stream that was created.
   *
   * @throws  LDAPException  If a problem is encountered while opening the file.
   */
  @NotNull()
  private InputStream openInputStream(@NotNull final File f)
          throws LDAPException
  {
    if (ldifEncryptionPassphraseFile.isPresent() &&
       (! ldifEncryptionPassphraseFileRead))
    {
      readPassphraseFile(ldifEncryptionPassphraseFile.getValue());
      ldifEncryptionPassphraseFileRead = true;
    }


    boolean closeStream = true;
    InputStream inputStream = null;
    try
    {
      inputStream = new FileInputStream(f);

      final ObjectPair<InputStream,char[]> p =
           ToolUtils.getPossiblyPassphraseEncryptedInputStream(
                inputStream, inputEncryptionPassphrases,
                (! ldifEncryptionPassphraseFile.isPresent()),
                INFO_LDIFSEARCH_ENTER_ENCRYPTION_PW.get(f.getName()),
                ERR_LDIFSEARCH_WRONG_ENCRYPTION_PW.get(), getOut(), getErr());
      inputStream = p.getFirst();
      addPassphrase(p.getSecond());

      inputStream = ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);
      closeStream = false;
      return inputStream;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDIFSEARCH_ERROR_OPENING_INPUT_FILE.get(f.getAbsolutePath(),
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
           ERR_LDIFSEARCH_CANNOT_READ_PW_FILE.get(f.getAbsolutePath(),
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
   * Creates an LDIF writer to write to the specified file.
   *
   * @param  f        The file to be written.
   * @param  ldapURL  The LDAP URL with which the file will be associated.  It
   *                  may be {@code null} if the file is shared across multiple
   *                  URLs.
   *
   * @return  The LDIF writer that was created.
   *
   * @throws  LDAPException  If a problem occurs while creating the LDIF writer.
   */
  @NotNull()
  private LDIFWriter createLDIFWriter(@NotNull final File f,
                                      @Nullable final LDAPURL ldapURL)
          throws LDAPException
  {
    OutputStream outputStream = null;
    boolean closeOutputStream = true;
    try
    {
      try
      {

        outputStream = new FileOutputStream(f,
             (! overwriteExistingOutputFile.isPresent()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDIFSEARCH_CANNOT_OPEN_OUTPUT_FILE.get(f.getAbsolutePath(),
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
                 INFO_LDIFSEARCH_PROMPT_OUTPUT_FILE_ENC_PW.get(),
                 INFO_LDIFSEARCH_CONFIRM_OUTPUT_FILE_ENC_PW.get(), getOut(),
                 getErr()).toCharArray();
          }

          outputStream = new PassphraseEncryptedOutputStream(passphrase,
               outputStream, null, true, true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDIFSEARCH_CANNOT_ENCRYPT_OUTPUT_FILE.get(
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
               ERR_LDIFSEARCH_CANNOT_COMPRESS_OUTPUT_FILE.get(
                    f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
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

      if (ldapURL != null)
      {
        try
        {
          ldifWriter.writeComment(
               INFO_LDIFSEARCH_ENTRIES_MATCHING_URL.get(ldapURL.toString()),
               false, true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
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
   * Indicates whether the given entry matches the criteria in the provided LDAP
   * URL.
   *
   * @param  url    The URL for which to make the determination.
   * @param  entry  The entry for which to make the determination.
   *
   * @return  {@code true} if the entry matches the criteria in the LDAP URL, or
   *          {@code false} if not.
   */
  private boolean urlMatchesEntry(@NotNull final LDAPURL url,
                                  @NotNull final Entry entry)
  {
    try
    {
      return (entry.matchesBaseAndScope(url.getBaseDN(), url.getScope()) &&
           url.getFilter().matchesEntry(entry));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Writes a line-wrapped, commented version of the provided message to
   * standard output.
   *
   * @param  message  The message to be written.
   */
  private void commentToOut(@NotNull final String message)
  {
    getOut().flush();
    for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
    {
      out("# " + line);
    }
    getOut().flush();
  }



  /**
   * Writes a line-wrapped, commented version of the provided message to
   * standard error.
   *
   * @param  message  The message to be written.
   */
  private void commentToErr(@NotNull final String message)
  {
    getErr().flush();
    for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
    {
      err("# " + line);
    }
    getErr().flush();
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
      commentToErr(message);
    }
    else
    {
      commentToOut(message);
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
           "--ldifFile", "data.ldif",
           "(uid=jdoe)"
         },
         INFO_LDIFSEARCH_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--ldifFile", "data.ldif",
           "--outputFile", "people.ldif",
           "--baseDN", "dc=example,dc=com",
           "--scope", "sub",
           "(objectClass=person)",
           "givenName",
           "sn",
           "cn",
         },
         INFO_LDIFSEARCH_EXAMPLE_2.get());

    return examples;
  }
}
