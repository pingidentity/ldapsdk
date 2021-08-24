/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StreamDirectoryValuesExtendedRequest;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPSDKThreadFactory;
import com.unboundid.util.MultiServerLDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.parallel.ParallelProcessor;
import com.unboundid.util.parallel.Result;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a tool that can be used to compare the contents of two
 * LDAPv3 servers and report the differences in an LDIF file that can be used to
 * update the source server to match the target.  It should work with any pair
 * of LDAPv3 servers, including servers of different types.
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
 * This tool can be used to determine whether two LDAP replicas are in sync.  It
 * can also account for replication delay by checking differing entries multiple
 * times.
 * <BR><BR>
 * At a minimum, the user must provide information needed to connect and
 * authenticate to the two servers to compare, as well as the base DN below
 * authenticate to the two servers to compare, as well as the base DN below
 * which to search (note that the empty base DN is not supported).  The user can
 * optionally also specify a filter used to identify which entries should be
 * compared.
 * <BR><BR>
 * This tool tries to compare the contents of both servers as quickly as
 * possible while also maintaining a low memory overhead and eliminating false
 * positives that result from entries that are temporarily out of sync as a
 * result of replication latencies.  It does this using the following approach:
 * <UL>
 *   <LI>
 *     Retrieve the DNs from each server in parallel.  For servers that
 *     advertise support for the {@link StreamDirectoryValuesExtendedRequest},
 *     then that operation will be used to retrieve the DNs.  Otherwise, a
 *     search will be used with the configured base DN, scope, and filter to
 *     retrieve all matching entries (without any attributes).
 *   </LI>
 *   <LI>
 *     For up to a configurable number of passes:
 *     <OL>
 *       <LI>
 *         Use a thread pool to iterate through all of the identified entry DNs,
 *         fetching and comparing each entry from both servers.  By default,
 *         multiple threads will be used to perform the comparison as fast as
 *         possible, but this can be configured as needed to adjust the
 *         performance impact on the directory servers.
 *       </LI>
 *       <LI>
 *         If the version of the entry retrieved from each server is the same,
 *         then it is considered in sync and will not be compared again.  If the
 *         entry differs between the source and target servers, and if there are
 *         no more passes to complete, then the differences will be computed and
 *         written in LDIF form to an output file.
 *       </LI>
 *       <LI>
 *         If any differing entries were identified, and if there are more
 *         passes remaining, then the tool will wait for a specified length of
 *         time before re-retrieving and re-comparing each of the entries that
 *         differed in the last pass.
 *       </LI>
 *     </OL>
 *   </LI>
 * </UL>
 * Note that even though the tool operates in parallel, it ensures that the
 * differences are written to the output file in an appropriate order to ensure
 * that they can be replayed.  The tool keeps the adds, modifies, and deletes
 * separate during processing and then joins them at the end in an appropriate
 * order (with deletes in reverse order to ensure that children are removed
 * before parents, followed by modifies, and finally adds).  Intermediate files
 * are used during processing to hold the add and modify records to minimize
 * memory consumption.
 * <BR><BR>
 * Note that the accounts used to run this tool must be sufficiently privileged
 * to perform the necessary processing, including being able to access all of
 * the appropriate entries (and all relevant attributes in those entries) in
 * each server.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPDiff
       extends MultiServerLDAPCommandLineTool
{
  /**
   * The column at which to wrap long lines.
   */
  static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The maximum number of entries to process in parallel in a batch.
   */
  private static final int MAX_ENTRIES_PER_BATCH = 1_000;



  /**
   * The default value that will be used for the default bind DN if none is
   * specified.
   */
  @NotNull private static final String DEFAULT_BIND_DN = "cn=Directory Manager";



  // A reference to the tool completion message for this tool.
  @NotNull private final AtomicReference<String> toolCompletionMessageRef;

  // The argument parser used by this program.
  @Nullable private ArgumentParser parser;

  // Arguments to use when processing.
  @Nullable private BooleanArgument byteForByteArg;
  @Nullable private BooleanArgument missingOnlyArg;
  @Nullable private BooleanArgument quietArg;
  @Nullable private DNArgument baseDNArg;
  @Nullable private DNArgument excludeBranchArg;
  @Nullable private FileArgument outputLDIFArg;
  @Nullable private FileArgument sourceDNsFileArg;
  @Nullable private FileArgument targetDNsFileArg;
  @Nullable private FilterArgument searchFilterArg;
  @Nullable private IntegerArgument numPassesArg;
  @Nullable private IntegerArgument numThreadsArg;
  @Nullable private IntegerArgument secondsBetweenPassesArg;
  @Nullable private IntegerArgument wrapColumnArg;
  @Nullable private ScopeArgument searchScopeArg;

  // Legacy arguments used only to provide compatibility with an older version
  // of this tool.
  @Nullable private BooleanArgument legacyTrustAllArg;
  @Nullable private DNArgument legacySourceBindDNArg;
  @Nullable private FileArgument legacyKeyStorePathArg;
  @Nullable private FileArgument legacyKeyStorePasswordFileArg;
  @Nullable private FileArgument legacyTargetBindPasswordFileArg;
  @Nullable private FileArgument legacyTrustStorePathArg;
  @Nullable private FileArgument legacyTrustStorePasswordFileArg;
  @Nullable private IntegerArgument legacySourcePortArg;
  @Nullable private StringArgument legacyCertNicknameArg;
  @Nullable private StringArgument legacyKeyStoreFormatArg;
  @Nullable private StringArgument legacyKeyStorePasswordArg;
  @Nullable private StringArgument legacySourceBindPasswordArg;
  @Nullable private StringArgument legacySourceHostArg;
  @Nullable private StringArgument legacyTargetHostArg;
  @Nullable private StringArgument legacyTrustStoreFormatArg;
  @Nullable private StringArgument legacyTrustStorePasswordArg;



  /**
   * Invokes this tool using the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this program.  It must
   *               not be {@code null} or empty.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(Math.min(resultCode.intValue(), 255));
    }
  }



  /**
   * Invokes this tool using the provided set of command-line arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.  It must
   *               not be {@code null} or empty.
   *
   * @return  A result code that indicates the result of tool processing.  A
   *          result code of {@link ResultCode#SUCCESS} indicates that all
   *          processing completed successfully and no differences were
   *          identified.  A result code of {@link ResultCode#COMPARE_FALSE}
   *          indicates that all processing completed successfully but that one
   *          or more differences were identified between the source and target
   *          servers.  Any other result code indicates that an error occurred
   *          during processing.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDAPDiff ldapDiff = new LDAPDiff(out, err);
    return ldapDiff.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided information.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public LDAPDiff(@Nullable final OutputStream out,
                  @Nullable final OutputStream err)
  {
    super(out, err, new String[] { "source", "target" }, null);

    toolCompletionMessageRef = new AtomicReference<>();

    parser = null;

    missingOnlyArg = null;
    quietArg = null;
    baseDNArg = null;
    excludeBranchArg = null;
    outputLDIFArg = null;
    sourceDNsFileArg = null;
    targetDNsFileArg = null;
    searchFilterArg = null;
    numPassesArg = null;
    numThreadsArg = null;
    secondsBetweenPassesArg = null;
    wrapColumnArg = null;
    searchScopeArg = null;

    legacyTrustAllArg = null;
    legacySourceBindDNArg = null;
    legacyKeyStorePathArg = null;
    legacyKeyStorePasswordFileArg = null;
    legacyTargetBindPasswordFileArg = null;
    legacyTrustStorePathArg = null;
    legacyTrustStorePasswordFileArg = null;
    legacySourcePortArg = null;
    legacyCertNicknameArg = null;
    legacyKeyStoreFormatArg = null;
    legacyKeyStorePasswordArg = null;
    legacySourceBindPasswordArg = null;
    legacySourceHostArg = null;
    legacyTargetHostArg = null;
    legacyTrustStoreFormatArg = null;
    legacyTrustStorePasswordArg = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldap-diff";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDAP_DIFF_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    final File pingIdentityServerRoot =
         InternalSDKHelper.getPingIdentityServerRoot();
    if (pingIdentityServerRoot == null)
    {
      return Arrays.asList(
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_2.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_3.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_4_NON_PING_DS.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_5_NON_PING_DS.get());
    }
    else
    {
      return Arrays.asList(
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_2.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_3.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_4_PING_DS.get(),
           INFO_LDAP_DIFF_TOOL_DESCRIPTION_5_PING_DS.get());
    }
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
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    options.setUsePooledSchema(true);
    return options;
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
    return Integer.MAX_VALUE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return INFO_LDAP_DIFF_TRAILING_ARGS_PLACEHOLDER.get();
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
    this.parser = parser;

    // Add the general arguments.
    baseDNArg = new DNArgument('b', "baseDN", true, 1,
         INFO_LDAP_DIFF_ARG_PLACEHOLDER_BASE_DN.get(),
         INFO_LDAP_DIFF_ARG_DESC_BASE_DN.get());
    baseDNArg.addLongIdentifier("base-dn", true);
    baseDNArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(baseDNArg);

    sourceDNsFileArg = new FileArgument(null, "sourceDNsFile", false, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_SOURCE_DNS_FILE.get(), true, true, true,
         false);
    sourceDNsFileArg.addLongIdentifier("source-dns-file", true);
    sourceDNsFileArg.addLongIdentifier("sourceDNFile", true);
    sourceDNsFileArg.addLongIdentifier("source-dn-file", true);
    sourceDNsFileArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(sourceDNsFileArg);

    targetDNsFileArg = new FileArgument(null, "targetDNsFile", false, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_TARGET_DNS_FILE.get(), true, true, true,
         false);
    targetDNsFileArg.addLongIdentifier("target-dns-file", true);
    targetDNsFileArg.addLongIdentifier("targetDNFile", true);
    targetDNsFileArg.addLongIdentifier("target-dn-file", true);
    targetDNsFileArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(targetDNsFileArg);

    excludeBranchArg = new DNArgument('B', "excludeBranch", false, 0, null,
         INFO_LDAP_DIFF_ARG_DESC_EXCLUDE_BRANCH.get());
    excludeBranchArg.addLongIdentifier("exclude-branch", true);
    excludeBranchArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(excludeBranchArg);

    searchFilterArg = new FilterArgument('f', "searchFilter", false, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_FILTER.get(),
         Filter.createPresenceFilter("objectClass"));
    searchFilterArg.addLongIdentifier("search-filter", true);
    searchFilterArg.addLongIdentifier("filter", true);
    searchFilterArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(searchFilterArg);

    searchScopeArg = new ScopeArgument('s', "searchScope", false, null,
         INFO_LDAP_DIFF_ARG_DESC_SCOPE.get(), SearchScope.SUB);
    searchScopeArg.addLongIdentifier("search-scope", true);
    searchScopeArg.addLongIdentifier("scope", true);
    searchScopeArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(searchScopeArg);

    outputLDIFArg = new FileArgument('o', "outputLDIF", true, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_OUTPUT_LDIF.get(), false, true, true, false);
    outputLDIFArg.addLongIdentifier("output-ldif", true);
    outputLDIFArg.addLongIdentifier("outputFile", true);
    outputLDIFArg.addLongIdentifier("output-file", true);
    outputLDIFArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(outputLDIFArg);

    wrapColumnArg = new IntegerArgument(null, "wrapColumn", false, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_WRAP_COLUMN.get(), 0, Integer.MAX_VALUE, 0);
    wrapColumnArg.addLongIdentifier("wrap-column", true);
    wrapColumnArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(wrapColumnArg);

    quietArg = new BooleanArgument('Q', "quiet", 1,
         INFO_LDAP_DIFF_ARG_DESC_QUIET.get());
    quietArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(quietArg);

    numThreadsArg = new IntegerArgument(null, "numThreads", false, 1,
         null, INFO_LDAP_DIFF_ARG_DESC_NUM_THREADS.get(), 1,
         Integer.MAX_VALUE, 20);
    numThreadsArg.addLongIdentifier("num-threads", true);
    numThreadsArg.addLongIdentifier("numConnections", true);
    numThreadsArg.addLongIdentifier("num-connections", true);
    numThreadsArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(numThreadsArg);

    numPassesArg = new IntegerArgument(null, "numPasses", false, 1, null,
         INFO_LDAP_DIFF_ARG_DESC_NUM_PASSES.get(), 1, Integer.MAX_VALUE, 3);
    numPassesArg.addLongIdentifier("num-passes", true);
    numPassesArg.addLongIdentifier("maxPasses", true);
    numPassesArg.addLongIdentifier("max-passes", true);
    numPassesArg.addLongIdentifier("maximum-Passes", true);
    numPassesArg.addLongIdentifier("maximum-passes", true);
    numPassesArg.addLongIdentifier("passes", true);
    numPassesArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(numPassesArg);

    secondsBetweenPassesArg = new IntegerArgument(null, "secondsBetweenPasses",
         false, 1, null, INFO_LDAP_DIFF_ARG_DESC_SECONDS_BETWEEN_PASSES.get(),
         0, Integer.MAX_VALUE, 2);
    secondsBetweenPassesArg.addLongIdentifier("seconds-between-passes", true);
    secondsBetweenPassesArg.addLongIdentifier("secondsBetweenPass", true);
    secondsBetweenPassesArg.addLongIdentifier("seconds-between-pass", true);
    secondsBetweenPassesArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(secondsBetweenPassesArg);

    byteForByteArg = new BooleanArgument(null, "byteForByte", 1,
         INFO_LDAP_DIFF_ARG_DESC_BYTE_FOR_BYTE.get());
    byteForByteArg.addLongIdentifier("byte-for-byte", true);
    byteForByteArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(byteForByteArg);

    missingOnlyArg = new BooleanArgument(null, "missingOnly", 1,
         INFO_LDAP_DIFF_ARG_DESC_MISSING_ONLY.get());
    missingOnlyArg.addLongIdentifier("missing-only", true);
    missingOnlyArg.addLongIdentifier("onlyMissing", true);
    missingOnlyArg.addLongIdentifier("only-missing", true);
    missingOnlyArg.setArgumentGroupName(
         INFO_LDAP_DIFF_ARG_GROUP_PROCESSING_ARGS.get());
    parser.addArgument(missingOnlyArg);


    // Add legacy arguments that will be used to help provide compatibility with
    // an older version of this tool.
    legacySourceHostArg = new StringArgument('h', null, false, 1, null, "");
    legacySourceHostArg.setHidden(true);
    parser.addArgument(legacySourceHostArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("sourceHostname"),
         legacySourceHostArg);

    legacySourcePortArg = new IntegerArgument('p', null, false, 1, null, "",
         1, 65535);
    legacySourcePortArg.setHidden(true);
    parser.addArgument(legacySourcePortArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("sourcePort"),
         legacySourcePortArg);

    legacySourceBindDNArg = new DNArgument('D', null, false, 1, null, "");
    legacySourceBindDNArg.setHidden(true);
    parser.addArgument(legacySourceBindDNArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("sourceBindDN"),
         legacySourceBindDNArg);

    legacySourceBindPasswordArg =
         new StringArgument('w', null, false, 1, null, "");
    legacySourceBindPasswordArg.setHidden(true);
    parser.addArgument(legacySourceBindPasswordArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceBindPassword"),
         legacySourceBindPasswordArg);

    legacyTargetHostArg = new StringArgument('O', null, false, 1, null, "");
    legacyTargetHostArg.setHidden(true);
    parser.addArgument(legacyTargetHostArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("targetHostname"),
         legacyTargetHostArg);

    legacyTargetBindPasswordFileArg = new FileArgument('F', null, false, 1,
         null, "", true, true, true, false);
    legacyTargetBindPasswordFileArg.setHidden(true);
    parser.addArgument(legacyTargetBindPasswordFileArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetBindPasswordFile"),
         legacyTargetBindPasswordFileArg);

    legacyTrustAllArg = new BooleanArgument('X', "trustAll", 1, "");
    legacyTrustAllArg.setHidden(true);
    parser.addArgument(legacyTrustAllArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("sourceTrustAll"),
         legacyTrustAllArg);
    parser.addExclusiveArgumentSet(parser.getNamedArgument("targetTrustAll"),
         legacyTrustAllArg);

    legacyKeyStorePathArg = new FileArgument('K', "keyStorePath", false, 1,
         null, "", true, true, true, false);
    legacyKeyStorePathArg.setHidden(true);
    parser.addArgument(legacyKeyStorePathArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceKeyStorePath"),
         legacyKeyStorePathArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetKeyStorePath"),
         legacyKeyStorePathArg);

    legacyKeyStorePasswordArg = new StringArgument('W', "keyStorePassword",
         false, 1, null, "");
    legacyKeyStorePasswordArg.setSensitive(true);
    legacyKeyStorePasswordArg.setHidden(true);
    parser.addArgument(legacyKeyStorePasswordArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceKeyStorePassword"),
         legacyKeyStorePasswordArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetKeyStorePassword"),
         legacyKeyStorePasswordArg);

    legacyKeyStorePasswordFileArg = new FileArgument('u',
         "keyStorePasswordFile", false, 1, null, "", true, true, true, false);
    legacyKeyStorePasswordFileArg.setHidden(true);
    parser.addArgument(legacyKeyStorePasswordFileArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceKeyStorePasswordFile"),
         legacyKeyStorePasswordFileArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetKeyStorePasswordFile"),
         legacyKeyStorePasswordFileArg);

    legacyKeyStoreFormatArg = new StringArgument(null, "keyStoreFormat", false,
         1, null, "");
    legacyKeyStoreFormatArg.setHidden(true);
    parser.addArgument(legacyKeyStoreFormatArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceKeyStoreFormat"),
         legacyKeyStoreFormatArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetKeyStoreFormat"),
         legacyKeyStoreFormatArg);

    legacyCertNicknameArg = new StringArgument('N', "certNickname", false, 1,
         null, "");
    legacyCertNicknameArg.setHidden(true);
    parser.addArgument(legacyCertNicknameArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceCertNickname"),
         legacyCertNicknameArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetCertNickname"),
         legacyCertNicknameArg);

    legacyTrustStorePathArg = new FileArgument('P', "trustStorePath", false, 1,
         null, "", true, true, true, false);
    legacyTrustStorePathArg.setHidden(true);
    parser.addArgument(legacyTrustStorePathArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceTrustStorePath"),
         legacyTrustStorePathArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetTrustStorePath"),
         legacyTrustStorePathArg);

    legacyTrustStorePasswordArg = new StringArgument(null, "trustStorePassword",
         false, 1, null, "");
    legacyTrustStorePasswordArg.setSensitive(true);
    legacyTrustStorePasswordArg.setHidden(true);
    parser.addArgument(legacyTrustStorePasswordArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceTrustStorePassword"),
         legacyTrustStorePasswordArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetTrustStorePassword"),
         legacyTrustStorePasswordArg);

    legacyTrustStorePasswordFileArg = new FileArgument('U',
         "trustStorePasswordFile", false, 1, null, "", true, true, true, false);
    legacyTrustStorePasswordFileArg.setHidden(true);
    parser.addArgument(legacyTrustStorePasswordFileArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceTrustStorePasswordFile"),
         legacyTrustStorePasswordFileArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetTrustStorePasswordFile"),
         legacyTrustStorePasswordFileArg);

    legacyTrustStoreFormatArg = new StringArgument(null, "trustStoreFormat",
         false, 1, null, "");
    legacyTrustStoreFormatArg.setHidden(true);
    parser.addArgument(legacyTrustStoreFormatArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("sourceTrustStoreFormat"),
         legacyTrustStoreFormatArg);
    parser.addExclusiveArgumentSet(
         parser.getNamedArgument("targetTrustStoreFormat"),
         legacyTrustStoreFormatArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // Make sure that the provided base DN was not empty.
    final DN baseDN = baseDNArg.getValue();
    if ((baseDN == null) || baseDN.isNullDN())
    {
      final String message = ERR_LDAP_DIFF_EMPTY_BASE_DN.get();
      toolCompletionMessageRef.compareAndSet(null, message);
      throw new ArgumentException(message);
    }


    // If any of the legacy arguments were provided, then use that argument to
    // set the value for the corresponding non-legacy argument(s).
    setArgumentValueFromArgument(legacySourceHostArg,
         "sourceHostname");
    setArgumentValueFromArgument(legacySourcePortArg,
         "sourcePort");
    setArgumentValueFromArgument(legacySourceBindDNArg,
         "sourceBindDN");
    setArgumentValueFromArgument(legacySourceBindPasswordArg,
         "sourceBindPassword");
    setArgumentValueFromArgument(legacyTargetHostArg,
         "targetHostname");
    setArgumentValueFromArgument(legacyTargetBindPasswordFileArg,
         "targetBindPasswordFile");
    setArgumentValueFromArgument(legacyKeyStorePathArg,
         "sourceKeyStorePath");
    setArgumentValueFromArgument(legacyKeyStorePathArg,
         "targetKeyStorePath");
    setArgumentValueFromArgument(legacyKeyStorePasswordArg,
         "sourceKeyStorePassword");
    setArgumentValueFromArgument(legacyKeyStorePasswordArg,
         "targetKeyStorePassword");
    setArgumentValueFromArgument(legacyKeyStorePasswordFileArg,
         "sourceKeyStorePasswordFile");
    setArgumentValueFromArgument(legacyKeyStorePasswordFileArg,
         "targetKeyStorePasswordFile");
    setArgumentValueFromArgument(legacyKeyStoreFormatArg,
         "sourceKeyStoreFormat");
    setArgumentValueFromArgument(legacyKeyStoreFormatArg,
         "targetKeyStoreFormat");
    setArgumentValueFromArgument(legacyCertNicknameArg,
         "sourceCertNickname");
    setArgumentValueFromArgument(legacyCertNicknameArg,
         "targetCertNickname");
    setArgumentValueFromArgument(legacyTrustStorePathArg,
         "sourceTrustStorePath");
    setArgumentValueFromArgument(legacyTrustStorePathArg,
         "targetTrustStorePath");
    setArgumentValueFromArgument(legacyTrustStorePasswordArg,
         "sourceTrustStorePassword");
    setArgumentValueFromArgument(legacyTrustStorePasswordArg,
         "targetTrustStorePassword");
    setArgumentValueFromArgument(legacyTrustStorePasswordFileArg,
         "sourceTrustStorePasswordFile");
    setArgumentValueFromArgument(legacyTrustStorePasswordFileArg,
         "targetTrustStorePasswordFile");
    setArgumentValueFromArgument(legacyTrustStoreFormatArg,
         "sourceTrustStoreFormat");
    setArgumentValueFromArgument(legacyTrustStoreFormatArg,
         "targetTrustStoreFormat");

    if (legacyTrustAllArg.isPresent())
    {
      setArgumentPresent("sourceTrustAll");
      setArgumentPresent("targetTrustAll");
    }


    // If no source bind DN was specified, then use a default of
    // "cn=Directory Manager".
    final DNArgument sourceBindDNArg = parser.getDNArgument("sourceBindDN");
    if (! sourceBindDNArg.isPresent())
    {
      try
      {
        final Method addValueMethod =
             Argument.class.getDeclaredMethod("addValue", String.class);
        addValueMethod.setAccessible(true);
        addValueMethod.invoke(sourceBindDNArg, DEFAULT_BIND_DN);

        final Method incrementOccurrencesMethod =
             Argument.class.getDeclaredMethod("incrementOccurrences");
        incrementOccurrencesMethod.setAccessible(true);
        incrementOccurrencesMethod.invoke(sourceBindDNArg);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAP_DIFF_CANNOT_SET_DEFAULT_BIND_DN.get(
                  DEFAULT_BIND_DN, sourceBindDNArg.getIdentifierString(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // If a source bind DN and password were provided but a target bind DN and
    // password were not, then use the source values for the target server.
    final DNArgument targetBindDNArg = parser.getDNArgument("targetBindDN");
    if (! targetBindDNArg.isPresent())
    {
      setArgumentValueFromArgument(sourceBindDNArg, "targetBindDN");
    }

    final StringArgument sourceBindPasswordArg =
         parser.getStringArgument("sourceBindPassword");
    final StringArgument targetBindPasswordArg =
         parser.getStringArgument("targetBindPassword");
    final FileArgument targetBindPasswordFileArg =
         parser.getFileArgument("targetBindPasswordFile");
    if (sourceBindPasswordArg.isPresent() &&
       (! (targetBindPasswordArg.isPresent() ||
            targetBindPasswordFileArg.isPresent())))
    {
      setArgumentValueFromArgument(sourceBindPasswordArg,
           "targetBindPassword");
    }

    final FileArgument sourceBindPasswordFileArg =
         parser.getFileArgument("sourceBindPasswordFile");
    if (sourceBindPasswordFileArg.isPresent() &&
       (! (targetBindPasswordArg.isPresent() ||
            targetBindPasswordFileArg.isPresent())))
    {
      setArgumentValueFromArgument(sourceBindPasswordFileArg,
           "targetBindPasswordFile");
    }
  }



  /**
   * Updates the specified non-legacy argument with the value from the given
   * legacy argument, if it is present.
   *
   * @param  legacyArgument         The legacy argument to use to set the value
   *                                of the specified non-legacy argument.  It
   *                                must not be {@code null}.
   * @param  nonLegacyArgumentName  The name of the non-legacy argument to
   *                                update with the value of the legacy
   *                                argument.  It must not be {@code null} and
   *                                must reference a defined argument that takes
   *                                a value.
   *
   * @throws  ArgumentException  If a problem occurs while attempting to set the
   *                             value of the specified non-legacy argument from
   *                             the given legacy argument.
   */
  private void setArgumentValueFromArgument(
                    @NotNull final Argument legacyArgument,
                    @NotNull final String nonLegacyArgumentName)
          throws ArgumentException
  {
    if (legacyArgument.isPresent())
    {
      try
      {
        final Argument nonLegacyArgument =
             parser.getNamedArgument(nonLegacyArgumentName);
        final Method addValueMethod =
             Argument.class.getDeclaredMethod("addValue", String.class);
        addValueMethod.setAccessible(true);

        final Method incrementOccurrencesMethod =
             Argument.class.getDeclaredMethod("incrementOccurrences");
        incrementOccurrencesMethod.setAccessible(true);

        for (final String valueString :
             legacyArgument.getValueStringRepresentations(false))
        {
          addValueMethod.invoke(nonLegacyArgument, valueString);
          incrementOccurrencesMethod.invoke(nonLegacyArgument);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        final String message = ERR_LDAP_DIFF_CANNOT_SET_ARG_FROM_LEGACY.get(
             legacyArgument.getIdentifierString(),
             nonLegacyArgumentName, StaticUtils.getExceptionMessage(e));
        toolCompletionMessageRef.compareAndSet(null, message);
        throw new ArgumentException(message, e);
      }
    }
  }



  /**
   * Updates the specified argument to indicate that it was provided on the
   * command line.
   *
   * @param  argumentName  The name of the argument to update as present.  It
   *                       must not be {@code null} and must reference a defined
   *                       Boolean argument.
   *
   * @throws  ArgumentException  If a problem occurs while attempting to mark
   *                             the specified argument as present.
   */
  private void setArgumentPresent(@NotNull final String argumentName)
          throws ArgumentException
  {
    try
    {
      final BooleanArgument argument = parser.getBooleanArgument(argumentName);
      final Method incrementOccurrencesMethod =
           Argument.class.getDeclaredMethod("incrementOccurrences");
      incrementOccurrencesMethod.setAccessible(true);
      incrementOccurrencesMethod.invoke(argument);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_LDAP_DIFF_CANNOT_SET_ARG_PRESENT.get(argumentName,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
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
    return toolCompletionMessageRef.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Establish connection pools to the source and target servers.
    LDAPConnectionPool sourcePool = null;
    LDAPConnectionPool targetPool = null;
    try
    {
      try
      {
        sourcePool = createConnectionPool(0, "SourceServer");
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        writeCompletionMessage(true,
             ERR_LDAP_DIFF_CANNOT_CONNECT_TO_SOURCE.get(
                  StaticUtils.getExceptionMessage(e)));
        return e.getResultCode();
      }

      try
      {
        targetPool = createConnectionPool(1, "TargetServer");
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        writeCompletionMessage(true,
             ERR_LDAP_DIFF_CANNOT_CONNECT_TO_TARGET.get(
                  StaticUtils.getExceptionMessage(e)));
        return e.getResultCode();
      }


      // Get the schema that we'll use for matching operations.  Retrieve it
      // from the target server.
      Schema schema = null;
      try
      {
        schema = targetPool.getSchema();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }


      // Get the base DN to use when identifying entries to compare.  Use the
      // schema if possible.
      DN baseDN;
      try
      {
        baseDN = new DN(baseDNArg.getStringValue(), schema);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        baseDN = baseDNArg.getValue();
      }


      // Get a set containing the DNs of the entries to examine from each of the
      // servers.
      final TreeSet<LDAPDiffCompactDN> dnsToExamine;
      try
      {
        dnsToExamine = getDNsToExamine(sourcePool, targetPool, baseDN, schema);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        writeCompletionMessage(true, e.getMessage());
        return e.getResultCode();
      }


      // Compare the entries in each server and write the results.
      try
      {
        final long[] entryCounts = identifyDifferences(sourcePool, targetPool,
             baseDN, schema, dnsToExamine);
        final long inSyncCount = entryCounts[0];
        final long addCount = entryCounts[1];
        final long delCount = entryCounts[2];
        final long modCount = entryCounts[3];
        final long missingCount = entryCounts[4];
        final long totalDifferenceCount = addCount + delCount + modCount;
        final long totalExaminedCount = inSyncCount + totalDifferenceCount;

        if (! quietArg.isPresent())
        {
          out();
        }

        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_PROCESSING_COMPLETE.get(getToolName()));
        out();

        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_TOTAL_EXAMINED.get(totalExaminedCount));
        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_ADD_COUNT.get(addCount));
        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_DEL_COUNT.get(delCount));
        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_MOD_COUNT.get(modCount));
        wrapOut(0, WRAP_COLUMN,
             INFO_LDAP_DIFF_SUMMARY_IN_SYNC_COUNT.get(inSyncCount));

        if (missingCount > 0)
        {
          wrapOut(0, WRAP_COLUMN,
               INFO_LDAP_DIFF_SUMMARY_MISSING_COUNT.get(missingCount));
        }

        out();

        if (totalDifferenceCount == 0)
        {
          writeCompletionMessage(false,
               INFO_LDAP_DIFF_SERVERS_IN_SYNC.get());
          return ResultCode.SUCCESS;
        }
        else
        {
          if (totalDifferenceCount == 1)
          {
            writeCompletionMessage(true,
                 WARN_LDAP_DIFF_DIFFERENCE_FOUND.get());
          }
          else
          {
            writeCompletionMessage(true,
                 WARN_LDAP_DIFF_DIFFERENCES_FOUND.get(totalDifferenceCount));
          }

          return ResultCode.COMPARE_FALSE;
        }
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        writeCompletionMessage(true,
             ERR_LDAP_DIFF_ERROR_IDENTIFYING_DIFFERENCES.get(
                  StaticUtils.getExceptionMessage(e)));
        return e.getResultCode();
      }
    }
    finally
    {
      if (sourcePool != null)
      {
        sourcePool.close();
      }

      if (targetPool != null)
      {
        targetPool.close();
      }
    }
  }



  /**
   * Creates a connection pool that is established to the sever with the
   * indicated index.
   *
   * @param  serverIndex  The index of the server to which the pool should be
   *                      established.
   * @param  name         The name to use for the connection pool.  It must not
   *                      be {@code null}.
   *
   * @return  The connection pool that was created.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection
   *                         pool.
   */
  @NotNull()
  private LDAPConnectionPool createConnectionPool(final int serverIndex,
                                                  @NotNull final String name)
          throws LDAPException
  {
    final LDAPConnectionPool pool = getConnectionPool(serverIndex, 1,
         numThreadsArg.getValue());
    pool.setRetryFailedOperationsDueToInvalidConnections(true);
    pool.setConnectionPoolName(name);
    return pool;
  }



  /**
   * Writes the provided message to standard output or standard error and sets
   * it as the tool completion message.
   *
   * @param  isError  Indicates whether the message represents an error
   *                  condition.
   * @param  message  The message to be written and set as the tool completion
   *                  message.  It must not be {@code null}.
   */
  private void writeCompletionMessage(final boolean isError,
                                      @NotNull final String message)
  {
    if (isError)
    {
      wrapErr(0, WRAP_COLUMN, message);
    }
    else
    {
      wrapOut(0, WRAP_COLUMN, message);
    }

    toolCompletionMessageRef.compareAndSet(null, message);
  }



  /**
   * Retrieves an ordered set of the DNs of the entries to examine from each of
   * the servers.  This will be done in parallel.
   *
   * @param  sourcePool  A connection pool that may be used to communicate with
   *                     the source server.  It must not be {@code null}.
   * @param  targetPool  A connection pool that may be used to communicate with
   *                     the target server.  It must not be {@code null}.
   * @param  baseDN      The base DN for entries to examine.  It must not be
   *                     {@code null}.
   * @param  schema      The schema to use during processing.  It may optionally
   *                     be {@code null} if no schema is available.
   *
   * @return  An ordered set of the DNs of the entries to exazmine from each of
   *          the servers.
   *
   * @throws  LDAPException  If a problem is encountered while obtaining the
   *                         set of DNs from the source or target server.
   */
  @NotNull()
  private TreeSet<LDAPDiffCompactDN> getDNsToExamine(
               @NotNull final LDAPConnectionPool sourcePool,
               @NotNull final LDAPConnectionPool targetPool,
               @NotNull final DN baseDN,
               @Nullable final Schema schema)
          throws LDAPException
  {
    if (! quietArg.isPresent())
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_LDAP_DIFF_IDENTIFYING_ENTRIES.get());
    }

    final TreeSet<LDAPDiffCompactDN> dnSet = new TreeSet<>();
    final LDAPDiffDNDumper sourceDNDumper = new LDAPDiffDNDumper(this,
         "LDAPDiff Source Server DN Dumper", sourceDNsFileArg.getValue(),
         sourcePool, baseDN, searchScopeArg.getValue(),
         excludeBranchArg.getValues(), searchFilterArg.getValue(), schema,
         missingOnlyArg.isPresent(), quietArg.isPresent(), dnSet);
    sourceDNDumper.start();

    final LDAPDiffDNDumper targetDNDumper = new LDAPDiffDNDumper(this,
         "LDAPDiff Target Server DN Dumper", targetDNsFileArg.getValue(),
         targetPool, baseDN, searchScopeArg.getValue(),
         excludeBranchArg.getValues(), searchFilterArg.getValue(), schema,
         missingOnlyArg.isPresent(), quietArg.isPresent(), dnSet);
    targetDNDumper.start();

    try
    {
      sourceDNDumper.join();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_ERROR_GETTING_SOURCE_DNS.get(
                StaticUtils.getExceptionMessage(e)));
    }

    final LDAPException sourceException =
         sourceDNDumper.getProcessingException();
    if (sourceException != null)
    {
      throw new LDAPException(sourceException.getResultCode(),
           ERR_LDAP_DIFF_ERROR_GETTING_SOURCE_DNS.get(
                sourceException.getMessage()),
           sourceException);
    }

    try
    {
      targetDNDumper.join();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_ERROR_GETTING_TARGET_DNS.get(
                StaticUtils.getExceptionMessage(e)));
    }

    final LDAPException targetException =
         targetDNDumper.getProcessingException();
    if (targetException != null)
    {
      throw new LDAPException(targetException.getResultCode(),
           ERR_LDAP_DIFF_ERROR_GETTING_TARGET_DNS.get(
                targetException.getMessage()),
           targetException);
    }

    if (! quietArg.isPresent())
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_LDAP_DIFF_IDENTIFIED_ENTRIES.get(dnSet.size()));
    }

    return dnSet;
  }



  /**
   * Examines all of the entries in the provided set and identifies differences
   * between the source and target servers.  The differences will be written to
   * output files, and the return value will provide information about the
   * number of entries in each result category.
   *
   * @param  sourcePool    A connection pool that may be used to communicate
   *                       with the source server.  It must not be {@code null}.
   * @param  targetPool    A connection pool that may be used to communicate
   *                       with the target server.  It must not be {@code null}.
   * @param  baseDN        The base DN for entries to examine.  It must not be
   *                       {@code null}.
   * @param  schema        The schema to use in processing.  It may optionally
   *                       be {@code null} if no schema is available.
   * @param  dnsToExamine  The set of DNs to examine.  It must not be
   *                       {@code null}.
   *
   * @return  An array of {@code long} values that provide the number of entries
   *          in each result category.  The array that is returned will contain
   *          five elements.  The first will be the number of entries that were
   *          found to be in sync between the source and target servers.  The
   *          second will be the number of entries that were present only in the
   *          target server and need to be added to the source server.  The
   *          third will be the number of entries that were present only in the
   *          source server and need to be removed.  The fourth will be the
   *          number of entries that were present in both servers but were not
   *          equivalent and therefore need to be modified in the source server.
   *          The fifth will be the number of entries that were initially
   *          identified but were subsequently not found in either server.
   *
   * @throws  LDAPException  If an unrecoverable error occurs during processing.
   */
  @NotNull()
  private long[] identifyDifferences(
                      @NotNull final LDAPConnectionPool sourcePool,
                      @NotNull final LDAPConnectionPool targetPool,
                      @NotNull final DN baseDN,
                      @Nullable final Schema schema,
                      @NotNull final TreeSet<LDAPDiffCompactDN> dnsToExamine)
          throws LDAPException
  {
    // Create LDIF writers that will be used to write the output files.  We want
    // to create the main output file even if we don't end up identifying any
    // changes, and it's also convenient to just go ahead and create the
    // temporary add and modify files now, too, even if we don't end up using
    // them.
    final File mergedOutputFile = outputLDIFArg.getValue();

    final File addFile = new File(mergedOutputFile.getAbsolutePath() + ".add");
    addFile.deleteOnExit();

    final File modFile = new File(mergedOutputFile.getAbsolutePath() + ".mod");
    modFile.deleteOnExit();

    long inSyncCount = 0L;
    long addCount = 0L;
    long deleteCount = 0L;
    long modifyCount = 0L;
    long missingCount = 0L;
    ParallelProcessor<LDAPDiffCompactDN,LDAPDiffProcessorResult>
         parallelProcessor = null;
    final String sourceHostPort =
         getServerHostPort("sourceHostname", "sourcePort");
    final String targetHostPort =
         getServerHostPort("targetHostname", "targetPort");
    final TreeSet<LDAPDiffCompactDN> missingEntryDNs = new TreeSet<>();
    try (LDIFWriter mergedWriter = createLDIFWriter(mergedOutputFile,
              INFO_LDAP_DIFF_MERGED_FILE_COMMENT.get(sourceHostPort,
                   targetHostPort));
         LDIFWriter addWriter = createLDIFWriter(addFile);
         LDIFWriter modWriter = createLDIFWriter(modFile))
    {
      // Create a parallel processor that will be used to retrieve and compare
      // entries from the source and target servers.
      final String[] attributes =
           parser.getTrailingArguments().toArray(StaticUtils.NO_STRINGS);

      final LDAPDiffProcessor processor = new LDAPDiffProcessor(sourcePool,
           targetPool, baseDN, schema, byteForByteArg.isPresent(), attributes,
           missingOnlyArg.isPresent());

      parallelProcessor = new ParallelProcessor<>(processor,
           new LDAPSDKThreadFactory("LDAPDiff Compare Processor", true),
           numThreadsArg.getValue(), 5);


      // Define variables that will be used to monitor progress and keep track
      // of information between passes.
      TreeSet<LDAPDiffCompactDN> currentPassDNs = dnsToExamine;
      TreeSet<LDAPDiffCompactDN> nextPassDNs = new TreeSet<>();
      final TreeSet<LDAPDiffCompactDN> deletedEntryDNs = new TreeSet<>();
      final List<LDAPDiffCompactDN> currentBatchOfDNs =
           new ArrayList<>(MAX_ENTRIES_PER_BATCH);


      // Process each pass, or until we confirm that there aren't any changes
      // between the source and target servers.
      for (int i=1; i <= numPassesArg.getValue(); i++)
      {
        final boolean isLastPass = (i == numPassesArg.getValue());

        if (! quietArg.isPresent())
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_LDAP_DIFF_STARTING_COMPARE_PASS.get(i,
                    numPassesArg.getValue(), currentPassDNs.size()));
        }


        // Process the changes in batches until we have gone through all of the
        // entries.
        nextPassDNs.clear();
        int differencesIdentifiedCount = 0;
        int processedCurrentPassCount = 0;
        final int totalCurrentPassCount = currentPassDNs.size();
        final Iterator<LDAPDiffCompactDN> dnIterator =
             currentPassDNs.iterator();
        while (dnIterator.hasNext())
        {
          // Build a batch of DNs.
          currentBatchOfDNs.clear();
          while (dnIterator.hasNext())
          {
            currentBatchOfDNs.add(dnIterator.next());
            dnIterator.remove();

            if (currentBatchOfDNs.size() >= MAX_ENTRIES_PER_BATCH)
            {
              break;
            }
          }

          // Process the batch of entries.
          final List<Result<LDAPDiffCompactDN,LDAPDiffProcessorResult>> results;
          try
          {
            results = parallelProcessor.processAll(currentBatchOfDNs);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_DIFF_ERROR_PROCESSING_BATCH.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }

          // Iterate through and handle the results.
          for (final Result<LDAPDiffCompactDN,LDAPDiffProcessorResult> result :
               results)
          {
            processedCurrentPassCount++;

            final Throwable exception = result.getFailureCause();
            if (exception != null)
            {
              if (exception instanceof LDAPException)
              {
                throw (LDAPException) exception;
              }
              else
              {
                throw new LDAPException(ResultCode.LOCAL_ERROR,
                     ERR_LDAP_DIFF_ERROR_COMPARING_ENTRY.get(
                          result.getInput().toDN(baseDN, schema).toString(),
                          StaticUtils.getExceptionMessage(exception)),
                     exception);
              }
            }

            final LDAPDiffProcessorResult resultOutput = result.getOutput();
            final ChangeType changeType = resultOutput.getChangeType();
            if (changeType == null)
            {
              // This indicates that either the entry is in sync between the
              // source and target servers or that it was missing from both
              // servers.  If it's the former, then we just need to increment
              // a counter.  If it's the latter, then we also need to hold onto
              // the DN for including in a comment at the end of the LDIF file.
              if (resultOutput.isEntryMissing())
              {
                missingCount++;
                missingEntryDNs.add(result.getInput());
              }
              else
              {
                inSyncCount++;
              }

              // This indicates that the entry is in sync between the source
              // and target servers.  We don't need to do anything in this case.
              inSyncCount++;
            }
            else if (! isLastPass)
            {
              // This entry is out of sync, but this isn't the last pass, so
              // just hold on to the DN so that we'll re-examine the entry on
              // the next pass.
              nextPassDNs.add(result.getInput());
              differencesIdentifiedCount++;
            }
            else
            {
              // The entry is out of sync, and this is the last pass.  If the
              // entry should be deleted, then capture the DN in a sorted list.
              // If it's an add or modify, then write it to an appropriate
              // temporary file.  In each case, update the appropriate counter.
              differencesIdentifiedCount++;
              switch (changeType)
              {
                case DELETE:
                  deletedEntryDNs.add(result.getInput());
                  deleteCount++;
                  break;

                case ADD:
                  addWriter.writeChangeRecord(
                       new LDIFAddChangeRecord(resultOutput.getEntry()),
                       WARN_LDAP_DIFF_COMMENT_ADDED_ENTRY.get(targetHostPort,
                            sourceHostPort));
                  addCount++;
                  break;

                case MODIFY:
                default:
                  modWriter.writeChangeRecord(
                       new LDIFModifyChangeRecord(resultOutput.getDN(),
                            resultOutput.getModifications()),
                       WARN_LDAP_DIFF_COMMENT_MODIFIED_ENTRY.get(sourceHostPort,
                            targetHostPort));
                  modifyCount++;
                  break;
              }
            }
          }

          // Write a progress message.
          if (! quietArg.isPresent())
          {
            final int percentComplete = Math.round(100.0f *
                 processedCurrentPassCount / totalCurrentPassCount);
            wrapOut(0, WRAP_COLUMN,
                 INFO_LDAP_DIFF_COMPARE_PROGRESS.get(processedCurrentPassCount,
                      totalCurrentPassCount, percentComplete,
                      differencesIdentifiedCount));
          }
        }


        // If this isn't the last pass, and if there are still outstanding
        // differences, then sleep before the next iteration.
        if (isLastPass)
        {
          break;
        }
        else if (nextPassDNs.isEmpty())
        {
          if (! quietArg.isPresent())
          {
            wrapOut(0, WRAP_COLUMN,
                 INFO_LDAP_DIFF_NO_NEED_FOR_ADDITIONAL_PASS.get());
          }
          break;
        }
        else
        {
          try
          {
            final int sleepTimeSeconds = secondsBetweenPassesArg.getValue();
            if (! quietArg.isPresent())
            {
              wrapOut(0, WRAP_COLUMN,
                   INFO_LDAP_DIFF_WAITING_BEFORE_NEXT_PASS.get(
                        sleepTimeSeconds));
            }

            Thread.sleep(TimeUnit.SECONDS.toMillis(sleepTimeSeconds));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }


        // Swap currentPassDNs (which will now be empty) and nextPassDN (which
        // contains the DNs of entries that were found out of sync in the
        // current pass) sets so that they will be correct for the next pass.
        final TreeSet<LDAPDiffCompactDN> emptyDNSet = currentPassDNs;
        currentPassDNs = nextPassDNs;
        nextPassDNs = emptyDNSet;
      }


      // If we've gotten here, then we've completed all of the passes.  If no
      // differences were identified, then write a comment indicating that to
      // the end of the LDIF file.
      if ((addCount == 0) && (deleteCount == 0) && (modifyCount == 0))
      {
        mergedWriter.writeComment(INFO_LDAP_DIFF_SERVERS_IN_SYNC.get(), true,
             false);
      }


      // If we've gotten here, then we've completed all of the passes.  If we've
      // identified any deleted entries, then add them to the output first (in
      // descending order so that children are deleted before parents).  The
      // modify and add records will be added later, after we've closed all of
      // the writers.
      if (! deletedEntryDNs.isEmpty())
      {
        mergedWriter.writeComment(INFO_LDAP_DIFF_COMMENT_DELETED_ENTRIES.get(),
             true, true);

        if (! quietArg.isPresent())
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_LDAP_DIFF_STARTING_DELETE_PASS.get(deleteCount));
        }

        int entryCount = 0;
        for (final LDAPDiffCompactDN compactDN :
             deletedEntryDNs.descendingSet())
        {
          final SearchResultEntry entry;
          final String dnString = compactDN.toDN(baseDN, schema).toString();
          try
          {
            entry = sourcePool.getEntry(dnString, attributes);
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);
            throw new LDAPException(e.getResultCode(),
                 ERR_LDAP_DIFF_CANNOT_GET_ENTRY_TO_DELETE.get(dnString,
                      StaticUtils.getExceptionMessage(e)),
                 e);

          }

          if (entry != null)
          {
            mergedWriter.writeComment(
                 INFO_LDAP_DIFF_COMMENT_DELETED_ENTRY.get(sourceHostPort,
                      targetHostPort),
                 false, false);
            mergedWriter.writeComment("", false, false);
            for (final String line : entry.toLDIF(75))
            {
              mergedWriter.writeComment(line, false, false);
            }

            mergedWriter.writeChangeRecord(
                 new LDIFDeleteChangeRecord(entry.getDN()));
          }

          entryCount++;
          if ((! quietArg.isPresent()) &&
               ((entryCount % MAX_ENTRIES_PER_BATCH) == 0))
          {
            final int percentComplete =
                 Math.round(100.0f * entryCount / deleteCount);
            wrapOut(0, WRAP_COLUMN,
                 INFO_LDAP_DIFF_DELETE_PROGRESS.get(entryCount,
                      deleteCount, percentComplete));
          }
        }

        if (! quietArg.isPresent())
        {
          final int percentComplete =
               Math.round(100.0f * entryCount / deleteCount);
          wrapOut(0, WRAP_COLUMN,
               INFO_LDAP_DIFF_DELETE_PROGRESS.get(entryCount, deleteCount,
                    percentComplete));
        }
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_ERROR_WRITING_OUTPUT.get(getToolName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (parallelProcessor != null)
      {
        try
        {
          parallelProcessor.shutdown();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }


    // If any modified entries were identified, then append the modify LDIF
    // file to the merged change file.
    if (modifyCount > 0L)
    {
      appendFileToFile(modFile, mergedOutputFile,
           INFO_LDAP_DIFF_COMMENT_ADDED_ENTRIES.get());
      modFile.delete();
    }


    // If any added entries were identified, then append the add LDIF file to
    // the merged change file.
    if (addCount > 0L)
    {
      appendFileToFile(addFile, mergedOutputFile,
           INFO_LDAP_DIFF_COMMENT_MODIFIED_ENTRIES.get());
      addFile.delete();
    }


    // If there are any missing entries, then update the merged LDIF file to
    // list them.
    if (! missingEntryDNs.isEmpty())
    {
      try (FileOutputStream outputStream =
                new FileOutputStream(mergedOutputFile, true);
           LDIFWriter ldifWriter = new LDIFWriter(outputStream))
      {
        ldifWriter.writeComment(INFO_LDAP_DIFF_COMMENT_MISSING_ENTRIES.get(),
             true, true);
        for (final LDAPDiffCompactDN missingEntryDN : missingEntryDNs)
        {
          ldifWriter.writeComment(
               INFO_LDAP_DIFF_COMMENT_MISSING_ENTRY.get(missingEntryDN.toDN(
                    baseDN, schema).toString()),
               false, true);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_DIFF_ERROR_WRITING_OUTPUT.get(getToolName(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    return new long[]
    {
      inSyncCount,
      addCount,
      deleteCount,
      modifyCount,
      missingCount
    };
  }



  /**
   * Retrieves a string representation of the address and port for the server
   * identified by the specified arguments.
   *
   * @param  hostnameArgName  The name of the argument used to specify the
   *                          hostname for the target server.  It must not be
   *                          {@code null}.
   * @param  portArgName      The name of the argument used to specify the port
   *                          of the target server.  It must not be
   *                          {@code null}.
   *
   * @return  A string representation of the address and port for the server
   *          identified by the specified arguments.
   */
  @NotNull()
  private String getServerHostPort(@NotNull final String hostnameArgName,
                                   @NotNull final String portArgName)
  {
    final StringArgument hostnameArg =
         parser.getStringArgument(hostnameArgName);
    final IntegerArgument portArg = parser.getIntegerArgument(portArgName);
    return hostnameArg.getValue() + ':' + portArg.getValue();
  }



  /**
   * Creates the LDIF writer that will be used when writing identified
   * differences.
   *
   * @param  ldifFile  The LDIF file to be written.  It must not be
   *                   {@code null}.
   * @param  comments  The set of comments to be included at the top of the
   *                   file.  It must not be {@code null} but may be empty.
   *
   * @return  The LDIF writer that was created.
   *
   * @throws  LDAPException  If a problem occurs while creating the LDIF writer.
   */
  @NotNull()
  private LDIFWriter createLDIFWriter(@NotNull final File ldifFile,
                                      @NotNull final String... comments)
          throws LDAPException
  {
    try
    {
      final LDIFWriter writer = new LDIFWriter(ldifFile);
      writer.setWrapColumn(wrapColumnArg.getValue());

      for (final String comment : comments)
      {
        writer.writeComment(comment, false, true);
      }

      return writer;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_CANNOT_CREATE_LDIF_WRITER.get(
                ldifFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Appends the contents of the specified file to the end of the indicated
   * file.
   *
   * @param  fileToAppend        The file whose contents should be appended to
   *                             the end of the indicated file.  It must not be
   *                             {@code null}, and the file must exist.
   * @param  fileToBeAppendedTo  The file to which the source file should be
   *                             appended.  It must not be {@code null}, and the
   *                             file must exist.
   * @param  comment             A comment that should be placed before the
   *                             content of the file to append.  It must not be
   *                             {@code null} or empty.
   *
   * @throws  LDAPException  If a problem occurs while reading from the file to
   *                         append or writing to the file to be appended to.
   */
  private void appendFileToFile(@NotNull final File fileToAppend,
                                @NotNull final File fileToBeAppendedTo,
                                @NotNull final String comment)
          throws LDAPException
  {
    try (FileInputStream inputStream = new FileInputStream(fileToAppend);
         FileOutputStream outputStream =
              new FileOutputStream(fileToBeAppendedTo, true))
    {
      outputStream.write(StaticUtils.getBytes(StaticUtils.EOL));
      for (final String line : StaticUtils.wrapLine(comment, (WRAP_COLUMN - 2)))
      {
        outputStream.write(StaticUtils.getBytes("# " + line + StaticUtils.EOL));
      }
      outputStream.write(StaticUtils.getBytes(StaticUtils.EOL));

      final byte[] buffer = new byte[1024 * 1024];
      while (true)
      {
        final int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          return;
        }

        outputStream.write(buffer, 0, bytesRead);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_ERROR_WRITING_OUTPUT.get(getToolName(),
                StaticUtils.getExceptionMessage(e)),
           e);
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
           "--sourceHostname", "source.example.com",
           "--sourcePort", "636",
           "--sourceUseSSL",
           "--sourceBindDN", "cn=Directory Manager",
           "--sourceBindPasswordFile", "/path/to/password.txt",
           "--targetHostname", "target.example.com",
           "--targetPort", "636",
           "--targetUseSSL",
           "--targetBindDN", "cn=Directory Manager",
           "--targetBindPasswordFile", "/path/to/password.txt",
           "--baseDN", "dc=example,dc=com",
           "--outputLDIF", "diff.ldif"
         },
         INFO_LDAP_DIFF_EXAMPLE.get());

    return examples;
  }
}
