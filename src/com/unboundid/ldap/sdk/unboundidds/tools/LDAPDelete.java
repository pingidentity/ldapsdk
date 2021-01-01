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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetBackendSetIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.HardDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.NoOpRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReplicationRepairRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RouteToBackendSetRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RouteToServerRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressReferentialIntegrityUpdatesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionPostConnectProcessor;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.SubtreeDeleter;
import com.unboundid.util.SubtreeDeleterResult;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that can be used to delete one or
 * more entries from an LDAP directory server.  The DNs of entries to delete
 * can be provided through command-line arguments, read from a file, or read
 * from standard input.  Alternately, the tool can delete entries matching a
 * given search filter.
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
public final class LDAPDelete
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which output should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // The set of arguments supported by this program.
  @Nullable private ArgumentParser parser = null;
  @Nullable private BooleanArgument authorizationIdentity = null;
  @Nullable private BooleanArgument clientSideSubtreeDelete = null;
  @Nullable private BooleanArgument continueOnError = null;
  @Nullable private BooleanArgument dryRun = null;
  @Nullable private BooleanArgument followReferrals = null;
  @Nullable private BooleanArgument getBackendSetID = null;
  @Nullable private BooleanArgument getServerID = null;
  @Nullable private BooleanArgument getUserResourceLimits = null;
  @Nullable private BooleanArgument hardDelete = null;
  @Nullable private BooleanArgument manageDsaIT = null;
  @Nullable private BooleanArgument neverRetry = null;
  @Nullable private BooleanArgument noOperation = null;
  @Nullable private BooleanArgument replicationRepair = null;
  @Nullable private BooleanArgument retryFailedOperations = null;
  @Nullable private BooleanArgument softDelete = null;
  @Nullable private BooleanArgument serverSideSubtreeDelete = null;
  @Nullable private BooleanArgument suppressReferentialIntegrityUpdates = null;
  @Nullable private BooleanArgument useAdministrativeSession = null;
  @Nullable private BooleanArgument useAssuredReplication = null;
  @Nullable private BooleanArgument verbose = null;
  @Nullable private ControlArgument bindControl = null;
  @Nullable private ControlArgument deleteControl = null;
  @Nullable private DNArgument entryDN = null;
  @Nullable private DNArgument proxyV1As = null;
  @Nullable private DNArgument searchBaseDN = null;
  @Nullable private DurationArgument assuredReplicationTimeout = null;
  @Nullable private FileArgument dnFile = null;
  @Nullable private FileArgument encryptionPassphraseFile = null;
  @Nullable private FileArgument deleteEntriesMatchingFiltersFromFile = null;
  @Nullable private FileArgument rejectFile = null;
  @Nullable private FilterArgument assertionFilter = null;
  @Nullable private FilterArgument deleteEntriesMatchingFilter = null;
  @Nullable private IntegerArgument ratePerSecond = null;
  @Nullable private IntegerArgument searchPageSize = null;
  @Nullable private StringArgument assuredReplicationLocalLevel = null;
  @Nullable private StringArgument assuredReplicationRemoteLevel = null;
  @Nullable private StringArgument characterSet = null;
  @Nullable private StringArgument getAuthorizationEntryAttribute = null;
  @Nullable private StringArgument operationPurpose = null;
  @Nullable private StringArgument preReadAttribute = null;
  @Nullable private StringArgument proxyAs = null;
  @Nullable private StringArgument routeToBackendSet = null;
  @Nullable private StringArgument routeToServer = null;

  // A reference to the reject writer that has been written, if it has been
  // created.
  @NotNull private final AtomicReference<LDIFWriter> rejectWriter =
       new AtomicReference<>();

  // The fixed-rate barrier (if any) used to enforce a rate limit on delete
  // operations.
  @Nullable private volatile FixedRateBarrier deleteRateLimiter = null;

  // The input stream from to use for standard input.
  @NotNull private final InputStream in;

  // The connection pool to use to communicate with the directory server.
  @Nullable private volatile LDAPConnectionPool connectionPool = null;

  // Controls to include in requests.
  @NotNull private volatile List<Control> deleteControls =
       Collections.emptyList();
  @NotNull private volatile List<Control> searchControls =
       Collections.emptyList();
  @NotNull private final List<RouteToBackendSetRequestControl>
       routeToBackendSetRequestControls = new ArrayList<>(10);

  // The subtree deleter to use to process client-side subtree deletes.
  @Nullable private volatile SubtreeDeleter subtreeDeleter = null;



  /**
   * Runs this tool with the provided command-line arguments.  It will use the
   * JVM-default streams for standard input, output, and error.
   *
   * @param  args  The command-line arguments to provide to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.in, System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Runs this tool with the provided streams and command-line arguments.
   *
   * @param  in    The input stream to use for standard input.  If this is
   *               {@code null}, then no standard input will be used.
   * @param  out   The output stream to use for standard output.  If this is
   *               {@code null}, then standard output will be suppressed.
   * @param  err   The output stream to use for standard error.  If this is
   *               {@code null}, then standard error will be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  The result code obtained when running the tool.  Any result code
   *          other than {@link ResultCode#SUCCESS} indicates an error.
   */
  @NotNull()
  public static ResultCode main(@Nullable final InputStream in,
                                @Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDAPDelete ldapDelete = new LDAPDelete(in, out, err);
    return ldapDelete.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided streams.  Standard
   * input will not be available.
   *
   * @param  out  The output stream to use for standard output.  If this is
   *              {@code null}, then standard output will be suppressed.
   * @param  err  The output stream to use for standard error.  If this is
   *              {@code null}, then standard error will be suppressed.
   */
  public LDAPDelete(@Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    this(null, out, err);
  }



  /**
   * Creates a new instance of this tool with the provided streams.
   *
   * @param  in   The input stream to use for standard input.  If this is
   *              {@code null}, then no standard input will be used.
   * @param  out  The output stream to use for standard output.  If this is
   *              {@code null}, then standard output will be suppressed.
   * @param  err  The output stream to use for standard error.  If this is
   *              {@code null}, then standard error will be suppressed.
   */
  public LDAPDelete(@Nullable final InputStream in,
                    @Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    super(out, err);

    if (in == null)
    {
      this.in = new ByteArrayInputStream(StaticUtils.NO_BYTES);
    }
    else
    {
      this.in = in;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldapdelete";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDAPDELETE_TOOL_DESCRIPTION.get();
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
    return Integer.MAX_VALUE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return INFO_LDAPDELETE_TRAILING_ARGS_PLACEHOLDER.get();
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
  public boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
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
  protected boolean supportsSSLDebugging()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
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


    //
    // Data Arguments
    //

    final String argGroupData = INFO_LDAPDELETE_ARG_GROUP_DATA.get();

    entryDN = new DNArgument('b', "entryDN", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_DN.get());
    entryDN.addLongIdentifier("entry-dn", true);
    entryDN.addLongIdentifier("dn", true);
    entryDN.addLongIdentifier("dnToDelete", true);
    entryDN.addLongIdentifier("dn-to-delete", true);
    entryDN.addLongIdentifier("entry", true);
    entryDN.addLongIdentifier("entryToDelete", true);
    entryDN.addLongIdentifier("entry-to-delete", true);
    entryDN.setArgumentGroupName(argGroupData);
    parser.addArgument(entryDN);


    dnFile = new FileArgument('f', "dnFile", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_DN_FILE.get(), true, true, true, false);
    dnFile.addLongIdentifier("dn-file", true);
    dnFile.addLongIdentifier("dnFilename", true);
    dnFile.addLongIdentifier("dn-filename", true);
    dnFile.addLongIdentifier("deleteEntriesWithDNsFromFile", true);
    dnFile.addLongIdentifier("delete-entries0-with-dns-from-file", true);
    dnFile.addLongIdentifier("file", true);
    dnFile.addLongIdentifier("filename", true);
    dnFile.setArgumentGroupName(argGroupData);
    parser.addArgument(dnFile);


    deleteEntriesMatchingFilter = new FilterArgument(null,
         "deleteEntriesMatchingFilter", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_DELETE_ENTRIES_MATCHING_FILTER.get());
    deleteEntriesMatchingFilter.addLongIdentifier(
         "delete-entries-matching-filter", true);
    deleteEntriesMatchingFilter.addLongIdentifier("deleteFilter", true);
    deleteEntriesMatchingFilter.addLongIdentifier("delete-filter", true);
    deleteEntriesMatchingFilter.addLongIdentifier("deleteSearchFilter", true);
    deleteEntriesMatchingFilter.addLongIdentifier("delete-search-filter", true);
    deleteEntriesMatchingFilter.addLongIdentifier("filter", true);
    deleteEntriesMatchingFilter.setArgumentGroupName(argGroupData);
    parser.addArgument(deleteEntriesMatchingFilter);


    deleteEntriesMatchingFiltersFromFile = new FileArgument(null,
         "deleteEntriesMatchingFiltersFromFile", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_DELETE_ENTRIES_MATCHING_FILTER_FILE.get(),
         true, true, true, false);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier(
         "delete-entries-matching-filters-from-file", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier(
         "deleteEntriesMatchingFilterFromFile", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier(
         "delete-entries-matching-filter-from-file", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier("deleteFilterFile",
         true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier("delete-filter-file",
         true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier(
         "deleteSearchFilterFile", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier(
         "delete-search-filter-file", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier("filterFile", true);
    deleteEntriesMatchingFiltersFromFile.addLongIdentifier("filter-file", true);
    deleteEntriesMatchingFiltersFromFile.setArgumentGroupName(argGroupData);
    parser.addArgument(deleteEntriesMatchingFiltersFromFile);


    searchBaseDN = new DNArgument(null, "searchBaseDN", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_SEARCH_BASE_DN.get(), DN.NULL_DN);
    searchBaseDN.addLongIdentifier("search-base-dn", true);
    searchBaseDN.addLongIdentifier("baseDN", true);
    searchBaseDN.addLongIdentifier("base-dn", true);
    searchBaseDN.setArgumentGroupName(argGroupData);
    parser.addArgument(searchBaseDN);


    searchPageSize = new IntegerArgument(null, "searchPageSize", false, 1,
         null, INFO_LDAPDELETE_ARG_DESC_SEARCH_PAGE_SIZE.get(), 1,
         Integer.MAX_VALUE);
    searchPageSize.addLongIdentifier("search-page-size", true);
    searchPageSize.addLongIdentifier("simplePagedResultsPageSize", true);
    searchPageSize.addLongIdentifier("simple-paged-results-page-size", true);
    searchPageSize.addLongIdentifier("pageSize", true);
    searchPageSize.addLongIdentifier("page-size", true);
    searchPageSize.setArgumentGroupName(argGroupData);
    parser.addArgument(searchPageSize);


    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null,
         INFO_LDAPDELETE_ARG_DESC_ENCRYPTION_PW_FILE.get(), true, true, true,
         false);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryptionPINFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-pin-file", true);
    encryptionPassphraseFile.setArgumentGroupName(argGroupData);
    parser.addArgument(encryptionPassphraseFile);


    characterSet = new StringArgument('i', "characterSet", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_CHARSET.get(),
         INFO_LDAPDELETE_ARG_DESC_CHARSET.get(), "UTF-8");
    characterSet.addLongIdentifier("character-set", true);
    characterSet.addLongIdentifier("charSet", true);
    characterSet.addLongIdentifier("char-set", true);
    characterSet.addLongIdentifier("encoding", true);
    characterSet.setArgumentGroupName(argGroupData);
    parser.addArgument(characterSet);


    rejectFile = new FileArgument('R', "rejectFile", false, 1, null,
         INFO_LDAPDELETE_ARG_DESC_REJECT_FILE.get(), false, true, true, false);
    rejectFile.addLongIdentifier("reject-file", true);
    rejectFile.addLongIdentifier("errorFile", true);
    rejectFile.addLongIdentifier("error-file", true);
    rejectFile.addLongIdentifier("failureFile", true);
    rejectFile.addLongIdentifier("failure-file", true);
    rejectFile.setArgumentGroupName(argGroupData);
    parser.addArgument(rejectFile);


    verbose = new BooleanArgument('v', "verbose", 1,
         INFO_LDAPDELETE_ARG_DESC_VERBOSE.get());
    verbose.setArgumentGroupName(argGroupData);
    parser.addArgument(verbose);

    // This argument has no effect.  It is provided for compatibility with a
    // legacy ldapdelete tool, where the argument was also offered but had no
    // effect.  In this tool, it is hidden.
    final BooleanArgument scriptFriendly = new BooleanArgument(null,
         "scriptFriendly", 1, INFO_LDAPDELETE_ARG_DESC_SCRIPT_FRIENDLY.get());
    scriptFriendly.addLongIdentifier("script-friendly", true);
    scriptFriendly.setArgumentGroupName(argGroupData);
    scriptFriendly.setHidden(true);
    parser.addArgument(scriptFriendly);



    //
    // Operation Arguments
    //

    final String argGroupOp = INFO_LDAPDELETE_ARG_GROUP_OPERATION.get();

    // NOTE:  The retryFailedOperations argument is now hidden, as we will retry
    // operations by default.  The neverRetry argument can be used to disable
    // this.
    retryFailedOperations = new BooleanArgument(null, "retryFailedOperations",
         1, INFO_LDAPDELETE_ARG_DESC_RETRY_FAILED_OPS.get());
    retryFailedOperations.addLongIdentifier("retry-failed-operations", true);
    retryFailedOperations.addLongIdentifier("retryFailedOps", true);
    retryFailedOperations.addLongIdentifier("retry-failed-ops", true);
    retryFailedOperations.addLongIdentifier("retry", true);
    retryFailedOperations.setArgumentGroupName(argGroupOp);
    retryFailedOperations.setHidden(true);
    parser.addArgument(retryFailedOperations);


    neverRetry = new BooleanArgument(null, "neverRetry", 1,
         INFO_LDAPDELETE_ARG_DESC_NEVER_RETRY.get());
    neverRetry.addLongIdentifier("never-retry", true);
    neverRetry.setArgumentGroupName(argGroupOp);
    parser.addArgument(neverRetry);


    dryRun = new BooleanArgument('n', "dryRun", 1,
         INFO_LDAPDELETE_ARG_DESC_DRY_RUN.get());
    dryRun.addLongIdentifier("dry-run", true);
    dryRun.setArgumentGroupName(argGroupOp);
    parser.addArgument(dryRun);


    continueOnError = new BooleanArgument('c', "continueOnError", 1,
         INFO_LDAPDELETE_ARG_DESC_CONTINUE_ON_ERROR.get());
    continueOnError.addLongIdentifier("continue-on-error", true);
    continueOnError.setArgumentGroupName(argGroupOp);
    parser.addArgument(continueOnError);


    followReferrals = new BooleanArgument(null, "followReferrals", 1,
         INFO_LDAPDELETE_ARG_DESC_FOLLOW_REFERRALS.get());
    followReferrals.addLongIdentifier("follow-referrals", true);
    followReferrals.setArgumentGroupName(argGroupOp);
    parser.addArgument(followReferrals);


    useAdministrativeSession = new BooleanArgument(null,
         "useAdministrativeSession", 1,
         INFO_LDAPDELETE_ARG_DESC_USE_ADMIN_SESSION.get());
    useAdministrativeSession.addLongIdentifier("use-administrative-session",
         true);
    useAdministrativeSession.addLongIdentifier("useAdminSession", true);
    useAdministrativeSession.addLongIdentifier("use-admin-session", true);
    useAdministrativeSession.setArgumentGroupName(argGroupOp);
    parser.addArgument(useAdministrativeSession);


    ratePerSecond = new IntegerArgument('r', "ratePerSecond", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_RATE_PER_SECOND.get(),
         INFO_LDAPDELETE_ARG_DESC_RATE_PER_SECOND.get(), 1, Integer.MAX_VALUE);
    ratePerSecond.addLongIdentifier("rate-per-second", true);
    ratePerSecond.addLongIdentifier("deletesPerSecond", true);
    ratePerSecond.addLongIdentifier("deletes-per-second", true);
    ratePerSecond.addLongIdentifier("operationsPerSecond", true);
    ratePerSecond.addLongIdentifier("operations-per-second", true);
    ratePerSecond.addLongIdentifier("opsPerSecond", true);
    ratePerSecond.addLongIdentifier("ops-per-second", true);
    ratePerSecond.setArgumentGroupName(argGroupOp);
    parser.addArgument(ratePerSecond);


    // This argument has no effect.  It is provided for compatibility with a
    // legacy ldapdelete tool, but this version only supports LDAPv3, so this
    // argument is hidden.
    final IntegerArgument ldapVersion = new IntegerArgument('V', "ldapVersion",
         false, 1, "{version}", INFO_LDAPDELETE_ARG_DESC_LDAP_VERSION.get(),
         3, 3, 3);
    ldapVersion.addLongIdentifier("ldap-version", true);
    ldapVersion.setArgumentGroupName(argGroupOp);
    ldapVersion.setHidden(true);
    parser.addArgument(ldapVersion);



    //
    // Control Arguments
    //

    final String argGroupControls = INFO_LDAPDELETE_ARG_GROUP_CONTROLS.get();

    clientSideSubtreeDelete = new BooleanArgument(null,
         "clientSideSubtreeDelete", 1,
         INFO_LDAPDELETE_ARG_DESC_CLIENT_SIDE_SUB_DEL.get());
    clientSideSubtreeDelete.addLongIdentifier("client-side-subtree-delete",
         true);
    clientSideSubtreeDelete.setArgumentGroupName(argGroupControls);
    parser.addArgument(clientSideSubtreeDelete);


    serverSideSubtreeDelete = new BooleanArgument('x',
         "serverSideSubtreeDelete", 1,
         INFO_LDAPDELETE_ARG_DESC_SERVER_SIDE_SUB_DEL.get());
    serverSideSubtreeDelete.addLongIdentifier("server-side-subtree-delete",
         true);
    serverSideSubtreeDelete.addLongIdentifier("deleteSubtree", true);
    serverSideSubtreeDelete.addLongIdentifier("delete-subtree", true);
    serverSideSubtreeDelete.addLongIdentifier("useSubtreeDeleteControl", true);
    serverSideSubtreeDelete.addLongIdentifier("use-subtree-delete-control",
         true);
    serverSideSubtreeDelete.setArgumentGroupName(argGroupControls);
    parser.addArgument(serverSideSubtreeDelete);


    softDelete = new BooleanArgument('s', "softDelete", 1,
         INFO_LDAPDELETE_ARG_DESC_SOFT_DELETE.get());
    softDelete.addLongIdentifier("soft-delete", true);
    softDelete.addLongIdentifier("useSoftDelete", true);
    softDelete.addLongIdentifier("use-soft-delete", true);
    softDelete.addLongIdentifier("useSoftDeleteControl", true);
    softDelete.addLongIdentifier("use-soft-delete-control", true);
    softDelete.setArgumentGroupName(argGroupControls);
    parser.addArgument(softDelete);


    hardDelete = new BooleanArgument(null, "hardDelete", 1,
         INFO_LDAPDELETE_ARG_DESC_HARD_DELETE.get());
    hardDelete.addLongIdentifier("hard-delete", true);
    hardDelete.addLongIdentifier("useHardDelete", true);
    hardDelete.addLongIdentifier("use-hard-delete", true);
    hardDelete.addLongIdentifier("useHardDeleteControl", true);
    hardDelete.addLongIdentifier("use-hard-delete-control", true);
    hardDelete.setArgumentGroupName(argGroupControls);
    parser.addArgument(hardDelete);


    proxyAs = new StringArgument('Y', "proxyAs", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_AUTHZ_ID.get(),
         INFO_LDAPDELETE_ARG_DESC_PROXY_AS.get());
    proxyAs.addLongIdentifier("proxy-as", true);
    proxyAs.addLongIdentifier("proxyV2As", true);
    proxyAs.addLongIdentifier("proxy-v2-as", true);
    proxyAs.addLongIdentifier("proxiedAuth", true);
    proxyAs.addLongIdentifier("proxied-auth", true);
    proxyAs.addLongIdentifier("proxiedAuthorization", true);
    proxyAs.addLongIdentifier("proxied-authorization", true);
    proxyAs.addLongIdentifier("useProxiedAuth", true);
    proxyAs.addLongIdentifier("use-proxied-auth", true);
    proxyAs.addLongIdentifier("useProxiedAuthorization", true);
    proxyAs.addLongIdentifier("use-proxied-authorization", true);
    proxyAs.addLongIdentifier("useProxiedAuthControl", true);
    proxyAs.addLongIdentifier("use-proxied-auth-control", true);
    proxyAs.addLongIdentifier("useProxiedAuthorizationControl", true);
    proxyAs.addLongIdentifier("use-proxied-authorization-control", true);
    proxyAs.setArgumentGroupName(argGroupControls);
    parser.addArgument(proxyAs);


    proxyV1As = new DNArgument(null, "proxyV1As", false, 1, null,
         INFO_LDAPDELETE_ARG_DESC_PROXY_V1_AS.get());
    proxyV1As.addLongIdentifier("proxy-v1-as", true);
    proxyV1As.setArgumentGroupName(argGroupControls);
    parser.addArgument(proxyV1As);


    manageDsaIT = new BooleanArgument(null, "useManageDsaIT", 1,
         INFO_LDAPDELETE_ARG_DESC_MANAGE_DSA_IT.get());
    manageDsaIT.addLongIdentifier("use-manage-dsa-it", true);
    manageDsaIT.addLongIdentifier("manageDsaIT", true);
    manageDsaIT.addLongIdentifier("manage-dsa-it", true);
    manageDsaIT.addLongIdentifier("manageDsaITControl", true);
    manageDsaIT.addLongIdentifier("manage-dsa-it-control", true);
    manageDsaIT.addLongIdentifier("useManageDsaITControl", true);
    manageDsaIT.addLongIdentifier("use-manage-dsa-it-control", true);
    manageDsaIT.setArgumentGroupName(argGroupControls);
    parser.addArgument(manageDsaIT);


    assertionFilter = new FilterArgument(null, "assertionFilter", false, 1,
         null, INFO_LDAPDELETE_ARG_DESC_ASSERTION_FILTER.get());
    assertionFilter.addLongIdentifier("assertion-filter", true);
    assertionFilter.addLongIdentifier("useAssertionFilter", true);
    assertionFilter.addLongIdentifier("use-assertion-filter", true);
    assertionFilter.addLongIdentifier("assertionControl", true);
    assertionFilter.addLongIdentifier("assertion-control", true);
    assertionFilter.addLongIdentifier("useAssertionControl", true);
    assertionFilter.addLongIdentifier("use-assertion-control", true);
    assertionFilter.setArgumentGroupName(argGroupControls);
    parser.addArgument(assertionFilter);


    preReadAttribute = new StringArgument(null, "preReadAttribute", false, 0,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ATTR.get(),
         INFO_LDAPDELETE_ARG_DESC_PRE_READ_ATTR.get());
    preReadAttribute.addLongIdentifier("pre-read-attribute", true);
    preReadAttribute.setArgumentGroupName(argGroupControls);
    parser.addArgument(preReadAttribute);


    noOperation = new BooleanArgument(null, "noOperation", 1,
         INFO_LDAPDELETE_ARG_DESC_NO_OP.get());
    noOperation.addLongIdentifier("no-operation", true);
    noOperation.addLongIdentifier("noOp", true);
    noOperation.addLongIdentifier("no-op", true);
    noOperation.setArgumentGroupName(argGroupControls);
    parser.addArgument(noOperation);


    getBackendSetID = new BooleanArgument(null, "getBackendSetID", 1,
         INFO_LDAPDELETE_ARG_DESC_GET_BACKEND_SET_ID.get());
    getBackendSetID.addLongIdentifier("get-backend-set-id", true);
    getBackendSetID.addLongIdentifier("useGetBackendSetID", true);
    getBackendSetID.addLongIdentifier("use-get-backend-set-id", true);
    getBackendSetID.addLongIdentifier("useGetBackendSetIDControl", true);
    getBackendSetID.addLongIdentifier("use-get-backend-set-id-control", true);
    getBackendSetID.setArgumentGroupName(argGroupControls);
    parser.addArgument(getBackendSetID);


    routeToBackendSet = new StringArgument(null, "routeToBackendSet", false, 0,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ROUTE_TO_BACKEND_SET.get(),
         INFO_LDAPDELETE_ARG_DESC_ROUTE_TO_BACKEND_SET.get());
    routeToBackendSet.addLongIdentifier("route-to-backend-set", true);
    routeToBackendSet.addLongIdentifier("useRouteToBackendSet", true);
    routeToBackendSet.addLongIdentifier("use0route-to-backend-set", true);
    routeToBackendSet.addLongIdentifier("useRouteToBackendSetControl", true);
    routeToBackendSet.addLongIdentifier("use-route-to-backend-set-control",
         true);
    routeToBackendSet.setArgumentGroupName(argGroupControls);
    parser.addArgument(routeToBackendSet);


    getServerID = new BooleanArgument(null, "getServerID", 1,
         INFO_LDAPDELETE_ARG_DESC_GET_SERVER_ID.get());
    getServerID.addLongIdentifier("get-server-id", true);
    getServerID.addLongIdentifier("getBackendServerID", true);
    getServerID.addLongIdentifier("get-backend-server-id", true);
    getServerID.addLongIdentifier("useGetServerID", true);
    getServerID.addLongIdentifier("use-get-server-id", true);
    getServerID.addLongIdentifier("useGetServerIDControl", true);
    getServerID.addLongIdentifier("use-get-server-id-control", true);
    getServerID.setArgumentGroupName(argGroupControls);
    parser.addArgument(getServerID);


    routeToServer = new StringArgument(null, "routeToServer", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ID.get(),
         INFO_LDAPDELETE_ARG_DESC_ROUTE_TO_SERVER.get());
    routeToServer.addLongIdentifier("route-to-server", true);
    routeToServer.addLongIdentifier("routeToBackendServer", true);
    routeToServer.addLongIdentifier("route-to-backend-server", true);
    routeToServer.addLongIdentifier("useRouteToServer", true);
    routeToServer.addLongIdentifier("use-route-to-server", true);
    routeToServer.addLongIdentifier("useRouteToBackendServer", true);
    routeToServer.addLongIdentifier("use-route-to-backend-server", true);
    routeToServer.addLongIdentifier("useRouteToServerControl", true);
    routeToServer.addLongIdentifier("use-route-to-server-control", true);
    routeToServer.addLongIdentifier("useRouteToBackendServerControl", true);
    routeToServer.addLongIdentifier("use-route-to-backend-server-control",
         true);
    routeToServer.setArgumentGroupName(argGroupControls);
    parser.addArgument(routeToServer);


    useAssuredReplication = new BooleanArgument(null, "useAssuredReplication",
         1, INFO_LDAPDELETE_ARG_DESC_USE_ASSURED_REPLICATION.get());
    useAssuredReplication.addLongIdentifier("use-assured-replication", true);
    useAssuredReplication.addLongIdentifier("assuredReplication", true);
    useAssuredReplication.addLongIdentifier("assured-replication", true);
    useAssuredReplication.addLongIdentifier("assuredReplicationControl", true);
    useAssuredReplication.addLongIdentifier("assured-replication-control",
         true);
    useAssuredReplication.addLongIdentifier("useAssuredReplicationControl",
         true);
    useAssuredReplication.addLongIdentifier("use-assured-replication-control",
         true);
    useAssuredReplication.setArgumentGroupName(argGroupControls);
    parser.addArgument(useAssuredReplication);


    assuredReplicationLocalLevel = new StringArgument(null,
         "assuredReplicationLocalLevel", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ASSURED_REPLICATION_LOCAL_LEVEL.get(),
         INFO_LDAPDELETE_ARG_DESC_ASSURED_REPLICATION_LOCAL_LEVEL.get(),
         StaticUtils.setOf(
              "none",
              "received-any-server",
              "processed-all-servers"));
    assuredReplicationLocalLevel.addLongIdentifier(
         "assured-replication-local-level", true);
    assuredReplicationLocalLevel.setArgumentGroupName(argGroupControls);
    parser.addArgument(assuredReplicationLocalLevel);


    assuredReplicationRemoteLevel = new StringArgument(null,
         "assuredReplicationRemoteLevel", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ASSURED_REPLICATION_REMOTE_LEVEL.get(),
         INFO_LDAPDELETE_ARG_DESC_ASSURED_REPLICATION_REMOTE_LEVEL.get(),
         StaticUtils.setOf(
              "none",
              "received-any-remote-location",
              "received-all-remote-locations",
              "processed-all-remote-servers"));
    assuredReplicationRemoteLevel.addLongIdentifier(
         "assured-replication-remote-level", true);
    assuredReplicationRemoteLevel.setArgumentGroupName(argGroupControls);
    parser.addArgument(assuredReplicationRemoteLevel);


    assuredReplicationTimeout = new DurationArgument(null,
         "assuredReplicationTimeout", false, null,
         INFO_LDAPDELETE_ARG_DESC_ASSURED_REPLICATION_TIMEOUT.get());
    assuredReplicationTimeout.addLongIdentifier("assured-replication-timeout",
         true);
    assuredReplicationTimeout.setArgumentGroupName(argGroupControls);
    parser.addArgument(assuredReplicationTimeout);


    replicationRepair = new BooleanArgument(null, "replicationRepair", 1,
         INFO_LDAPDELETE_ARG_DESC_REPLICATION_REPAIR.get());
    replicationRepair.addLongIdentifier("replication-repair", true);
    replicationRepair.addLongIdentifier("replicationRepairControl", true);
    replicationRepair.addLongIdentifier("replication-repair-control", true);
    replicationRepair.addLongIdentifier("useReplicationRepair", true);
    replicationRepair.addLongIdentifier("use-replication-repair", true);
    replicationRepair.addLongIdentifier("useReplicationRepairControl", true);
    replicationRepair.addLongIdentifier("use-replication-repair-control", true);
    replicationRepair.setArgumentGroupName(argGroupControls);
    parser.addArgument(replicationRepair);


    suppressReferentialIntegrityUpdates = new BooleanArgument(null,
         "suppressReferentialIntegrityUpdates", 1,
         INFO_LDAPDELETE_ARG_DESC_SUPPRESS_REFINT_UPDATES.get());
    suppressReferentialIntegrityUpdates.addLongIdentifier(
         "suppress-referential-integrity-updates", true);
    suppressReferentialIntegrityUpdates.addLongIdentifier(
         "useSuppressReferentialIntegrityUpdates", true);
    suppressReferentialIntegrityUpdates.addLongIdentifier(
         "use-suppress-referential-integrity-updates", true);
    suppressReferentialIntegrityUpdates.addLongIdentifier(
         "useSuppressReferentialIntegrityUpdatesControl", true);
    suppressReferentialIntegrityUpdates.addLongIdentifier(
         "use-suppress-referential-integrity-updates-control", true);
    suppressReferentialIntegrityUpdates.setArgumentGroupName(argGroupControls);
    parser.addArgument(suppressReferentialIntegrityUpdates);


    operationPurpose = new StringArgument(null, "operationPurpose", false, 1,
         null, INFO_LDAPDELETE_ARG_DESC_OP_PURPOSE.get());
    operationPurpose.addLongIdentifier("operation-purpose", true);
    operationPurpose.addLongIdentifier("operationPurposeControl", true);
    operationPurpose.addLongIdentifier("operation-purpose-control", true);
    operationPurpose.addLongIdentifier("useOperationPurpose", true);
    operationPurpose.addLongIdentifier("use-operation-purpose", true);
    operationPurpose.addLongIdentifier("useOperationPurposeControl", true);
    operationPurpose.addLongIdentifier("use-operation-purpose-control", true);
    operationPurpose.setArgumentGroupName(argGroupControls);
    parser.addArgument(operationPurpose);


    authorizationIdentity = new BooleanArgument('E', "authorizationIdentity",
         1, INFO_LDAPDELETE_ARG_DESC_AUTHZ_ID.get());
    authorizationIdentity.addLongIdentifier("authorization-identity", true);
    authorizationIdentity.addLongIdentifier("useAuthorizationIdentity", true);
    authorizationIdentity.addLongIdentifier("use-authorization-identity", true);
    authorizationIdentity.addLongIdentifier(
         "useAuthorizationIdentityControl", true);
    authorizationIdentity.addLongIdentifier(
         "use-authorization-identity-control", true);
    authorizationIdentity.setArgumentGroupName(argGroupControls);
    parser.addArgument(authorizationIdentity);


    getAuthorizationEntryAttribute = new StringArgument(null,
         "getAuthorizationEntryAttribute", false, 0,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ATTR.get(),
         INFO_LDAPDELETE_ARG_DESC_GET_AUTHZ_ENTRY_ATTR.get());
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authorization-entry-attribute", true);
    getAuthorizationEntryAttribute.setArgumentGroupName(argGroupControls);
    parser.addArgument(getAuthorizationEntryAttribute);


    getUserResourceLimits = new BooleanArgument(null, "getUserResourceLimits",
         1, INFO_LDAPDELETE_ARG_DESC_GET_USER_RESOURCE_LIMITS.get());
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits", true);
    getUserResourceLimits.addLongIdentifier("getUserResourceLimitsControl",
         true);
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits-control",
         true);
    getUserResourceLimits.addLongIdentifier("useGetUserResourceLimits", true);
    getUserResourceLimits.addLongIdentifier("use-get-user-resource-limits",
         true);
    getUserResourceLimits.addLongIdentifier(
         "useGetUserResourceLimitsControl", true);
    getUserResourceLimits.addLongIdentifier(
         "use-get-user-resource-limits-control", true);
    getUserResourceLimits.setArgumentGroupName(argGroupControls);
    parser.addArgument(getUserResourceLimits);


    deleteControl = new ControlArgument('J', "deleteControl", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_DELETE_CONTROL.get());
    deleteControl.addLongIdentifier("delete-control", true);
    deleteControl.addLongIdentifier("operationControl", true);
    deleteControl.addLongIdentifier("operation-control", true);
    deleteControl.addLongIdentifier("control", true);
    deleteControl.setArgumentGroupName(argGroupControls);
    parser.addArgument(deleteControl);


    bindControl = new ControlArgument(null, "bindControl", false, 0, null,
         INFO_LDAPDELETE_ARG_DESC_BIND_CONTROL.get());
    bindControl.addLongIdentifier("bind-control", true);
    bindControl.setArgumentGroupName(argGroupControls);
    parser.addArgument(bindControl);



    //
    // Argument Constraints
    //

    // At most one argument may be provided to select the entries to delete.
    parser.addExclusiveArgumentSet(entryDN, dnFile, deleteEntriesMatchingFilter,
         deleteEntriesMatchingFiltersFromFile);

    // The searchBaseDN argument can only be used if identifying entries with
    // search filters.
    parser.addDependentArgumentSet(searchBaseDN, deleteEntriesMatchingFilter,
         deleteEntriesMatchingFiltersFromFile);

    // The search page size argument can only be used if identifying entries
    // with search filters or performing a client-side subtree delete.
    parser.addDependentArgumentSet(searchPageSize, deleteEntriesMatchingFilter,
         deleteEntriesMatchingFiltersFromFile, clientSideSubtreeDelete);

    // Follow referrals and manage DSA IT can't be used together.
    parser.addExclusiveArgumentSet(followReferrals, manageDsaIT);

    // Client-side and server-side subtree delete can't be used together.
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete,
         serverSideSubtreeDelete);

    // A lot of options can't be used in conjunction with client-side
    // subtree delete.
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, followReferrals);
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, preReadAttribute);
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, getBackendSetID);
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, getServerID);
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, noOperation);
    parser.addExclusiveArgumentSet(clientSideSubtreeDelete, dryRun);

    // Soft delete and hard delete can't be used together.
    parser.addExclusiveArgumentSet(softDelete, hardDelete);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // Trailing arguments can only be used if none of the other arguments used
    // to identify entries to delete are provided.
    if (! parser.getTrailingArguments().isEmpty())
    {
      for (final Argument a :
           Arrays.asList(entryDN, dnFile, deleteEntriesMatchingFilter,
                deleteEntriesMatchingFiltersFromFile))
      {
        if (a.isPresent())
        {
          throw new ArgumentException(
               ERR_LDAPDELETE_TRAILING_ARG_CONFLICT.get(
                    a.getIdentifierString()));
        }
      }
    }


    // If we should use the route to backend set request control, then validate
    // and pre-create those controls.
    if (routeToBackendSet.isPresent())
    {
      final List<String> values = routeToBackendSet.getValues();
      final Map<String,List<String>> idsByRP = new LinkedHashMap<>(
           StaticUtils.computeMapCapacity(values.size()));
      for (final String value : values)
      {
        final int colonPos = value.indexOf(':');
        if (colonPos <= 0)
        {
          throw new ArgumentException(
               ERR_LDAPDELETE_ROUTE_TO_BACKEND_SET_INVALID_FORMAT.get(value,
                    routeToBackendSet.getIdentifierString()));
        }

        final String rpID = value.substring(0, colonPos);
        final String bsID = value.substring(colonPos+1);

        List<String> idsForRP = idsByRP.get(rpID);
        if (idsForRP == null)
        {
          idsForRP = new ArrayList<>(values.size());
          idsByRP.put(rpID, idsForRP);
        }
        idsForRP.add(bsID);
      }

      for (final Map.Entry<String,List<String>> e : idsByRP.entrySet())
      {
        final String rpID = e.getKey();
        final List<String> bsIDs = e.getValue();
        routeToBackendSetRequestControls.add(
             RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(
                  true, rpID, bsIDs));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Control> getBindControls()
  {
    final ArrayList<Control> bindControls = new ArrayList<>(10);

    if (bindControl.isPresent())
    {
      bindControls.addAll(bindControl.getValues());
    }

    if (authorizationIdentity.isPresent())
    {
      bindControls.add(new AuthorizationIdentityRequestControl(true));
    }

    if (getAuthorizationEntryAttribute.isPresent())
    {
      bindControls.add(new GetAuthorizationEntryRequestControl(true, true,
           getAuthorizationEntryAttribute.getValues()));
    }

    if (getUserResourceLimits.isPresent())
    {
      bindControls.add(new GetUserResourceLimitsRequestControl(true));
    }

    return bindControls;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsMultipleServers()
  {
    // We will support providing information about multiple servers.  This tool
    // will not communicate with multiple servers concurrently, but it can
    // accept information about multiple servers in the event that a large set
    // of changes is to be processed and a server goes down in the middle of
    // those changes.  In this case, we can resume processing on a newly-created
    // connection, possibly to a different server.
    return true;
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
    options.setFollowReferrals(followReferrals.isPresent());
    options.setUnsolicitedNotificationHandler(this);
    options.setResponseTimeoutMillis(0L);

    return options;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the controls that should be included in search and delete requests.
    searchControls = getSearchControls();
    deleteControls = getDeleteControls();

    // If the ratePerSecond argument was provided, then create the fixed-rate
    // barrier.
    if (ratePerSecond.isPresent())
    {
      deleteRateLimiter = new FixedRateBarrier(1000L, ratePerSecond.getValue());
    }

    // Create a subtree deleter instance if appropriate.
    if (clientSideSubtreeDelete.isPresent())
    {
      subtreeDeleter = new SubtreeDeleter();
      subtreeDeleter.setAdditionalSearchControls(searchControls);
      subtreeDeleter.setAdditionalSearchControls(deleteControls);
      subtreeDeleter.setDeleteRateLimiter(deleteRateLimiter);
      if (searchPageSize.isPresent())
      {
        subtreeDeleter.setSimplePagedResultsPageSize(searchPageSize.getValue());
      }
    }

    // If the encryptionPassphraseFile argument was provided, then read that
    // passphrase.
    final char[] encryptionPassphrase;
    if (encryptionPassphraseFile.isPresent())
    {
      try
      {
        encryptionPassphrase = getPasswordFileReader().readPassword(
             encryptionPassphraseFile.getValue());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        commentToErr(e.getMessage());
        return e.getResultCode();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        commentToErr(ERR_LDAPDELETE_CANNOT_READ_ENCRYPTION_PW_FILE.get(
             encryptionPassphraseFile.getValue().getAbsolutePath(),
             StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      encryptionPassphrase = null;
    }


    // If the character set argument was specified, then make sure it's valid.
    final Charset charset;
    try
    {
      charset = Charset.forName(characterSet.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      commentToErr(ERR_LDAPDELETE_UNSUPPORTED_CHARSET.get(
           characterSet.getValue()));
      return ResultCode.PARAM_ERROR;
    }


    // Get the connection pool.
    final StartAdministrativeSessionPostConnectProcessor p;
    if (useAdministrativeSession.isPresent())
    {
      p = new StartAdministrativeSessionPostConnectProcessor(
           new StartAdministrativeSessionExtendedRequest(getToolName(),
                true));
    }
    else
    {
      p = null;
    }

    try
    {
      connectionPool = getConnectionPool(1, 2, 0, p, null, true,
           new ReportBindResultLDAPConnectionPoolHealthCheck(this, true,
                verbose.isPresent()));
      connectionPool.setRetryFailedOperationsDueToInvalidConnections(
           (! neverRetry.isPresent()));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);

      // Unable to create the connection pool, which means that either the
      // connection could not be established or the attempt to authenticate
      // the connection failed.  If the bind failed, then the report bind
      // result health check should have already reported the bind failure.
      // If the failure was something else, then display that failure result.
      if (e.getResultCode() != ResultCode.INVALID_CREDENTIALS)
      {
        for (final String line :
             ResultUtils.formatResult(e, true, 0, WRAP_COLUMN))
        {
          err(line);
        }
      }
      return e.getResultCode();
    }


    // Figure out the method that we'll identify the entries to delete and
    // take the appropriate action.
    final AtomicReference<ResultCode> returnCode = new AtomicReference<>();
    if (entryDN.isPresent())
    {
      deleteFromEntryDNArgument(returnCode);
    }
    else if (dnFile.isPresent())
    {
      deleteFromDNFile(returnCode, charset, encryptionPassphrase);
    }
    else if (deleteEntriesMatchingFilter.isPresent())
    {
      deleteFromFilters(returnCode);
    }
    else if (deleteEntriesMatchingFiltersFromFile.isPresent())
    {
      deleteFromFilterFile(returnCode, charset, encryptionPassphrase);
    }
    else if (! parser.getTrailingArguments().isEmpty())
    {
      deleteFromTrailingArguments(returnCode);
    }
    else
    {
      deleteFromStandardInput(returnCode, charset, encryptionPassphrase);
    }


    // Close the reject writer.
    final LDIFWriter rw = rejectWriter.get();
    if (rw != null)
    {
      try
      {
        rw.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        commentToErr(ERR_LDAPDELETE_ERROR_CLOSING_REJECT_WRITER.get(
             rejectFile.getValue().getAbsolutePath(),
             StaticUtils.getExceptionMessage(e)));
        returnCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
      }
    }


    // Close the connection pool.
    connectionPool.close();


    returnCode.compareAndSet(null, ResultCode.SUCCESS);
    return returnCode.get();
  }



  /**
   * Deletes entries whose DNs are specified in the entryDN argument.
   *
   * @param  returnCode  A reference that should be updated with the result code
   *                     from the first failure that is encountered.  It must
   *                     not be {@code null}, but may be unset.
   */
  private void deleteFromEntryDNArgument(
                    @NotNull final AtomicReference<ResultCode> returnCode)
  {
    for (final DN dn : entryDN.getValues())
    {
      if ((! deleteEntry(dn.toString(), returnCode)) &&
           (! continueOnError.isPresent()))
      {
        return;
      }
    }
  }



  /**
   * Deletes entries whose DNs are contained in the files provided to the dnFile
   * argument.
   *
   * @param  returnCode            A reference that should be updated with the
   *                               result code from the first failure that is
   *                               encountered.  It must not be {@code null},
   *                               but may be unset.
   * @param  charset               The character set to use when reading the
   *                               data from the file.  It must not be
   *                               {@code null}.
   * @param  encryptionPassphrase  The passphrase to use to decrypt the data
   *                               read from the file if it happens to be
   *                               encrypted.  This may be {@code null} if the
   *                               user should be interactively prompted for the
   *                               passphrase if a file happens to be encrypted.
   */
  private void deleteFromDNFile(
                    @NotNull final AtomicReference<ResultCode> returnCode,
                    @NotNull final Charset charset,
                    @Nullable final char[] encryptionPassphrase)
  {
    final List<char[]> potentialPassphrases =
         new ArrayList<>(dnFile.getValues().size());
    if (encryptionPassphrase != null)
    {
      potentialPassphrases.add(encryptionPassphrase);
    }

    for (final File f : dnFile.getValues())
    {
      if (verbose.isPresent())
      {
        commentToOut(INFO_LDAPDELETE_READING_DNS_FROM_FILE.get(
             f.getAbsolutePath()));
        out();
      }

      try (FileInputStream fis = new FileInputStream(f))
      {
        if ((! deleteDNsFromInputStream(returnCode, fis, charset,
                    potentialPassphrases)) &&
             (! continueOnError.isPresent()))
        {
          return;
        }
      }
      catch (final Exception e)
      {
        commentToErr(ERR_LDAPDELETE_ERROR_OPENING_DN_FILE.get(
             f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
        if (! continueOnError.isPresent())
        {
          return;
        }
      }
    }
  }



  /**
   * Deletes entries whose DNs are read from the provided input stream.
   *
   * @param  returnCode            A reference that should be updated with the
   *                               result code from the first failure that is
   *                               encountered.  It must not be {@code null},
   *                               but may be unset.
   * @param  inputStream           The input stream from which the data is to be
   *                               read.
   * @param  charset               The character set to use when reading the
   *                               data from the input stream.  It must not be
   *                               {@code null}.
   * @param  potentialPassphrases  A list of the potential passphrases that may
   *                               be used to decrypt data read from the
   *                               provided input stream.  It must not be
   *                               {@code null}, and must be updatable, but may
   *                               be empty.
   *
   * @return  {@code true} if all processing completed successfully, or
   *          {@code false} if not.
   *
   * @throws  IOException  If an error occurs while trying to read data from the
   *                       input stream or create the buffered reader.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    attempting to interact with encrypted
   *                                    data read from the input stream.
   */
  private boolean deleteDNsFromInputStream(
                       @NotNull final AtomicReference<ResultCode> returnCode,
                       @NotNull final InputStream inputStream,
                       @NotNull final Charset charset,
                       @NotNull final List<char[]> potentialPassphrases)
          throws IOException, GeneralSecurityException
  {
    boolean successful = true;
    long lineNumber = 0;

    final BufferedReader reader =
         getBufferedReader(inputStream, charset, potentialPassphrases);
    while (true)
    {
      final String line = reader.readLine();
      lineNumber++;
      if (line == null)
      {
        return successful;
      }

      if (line.isEmpty() || line.startsWith("#"))
      {
        // The line is empty or contains a comment.  Ignore it.
      }
      else
      {
        // This is the DN of the entry to delete.
        if (! deleteDNFromInputStream(returnCode, line))
        {
          if (continueOnError.isPresent())
          {
            successful = false;
          }
          else
          {
            return false;
          }
        }
      }
    }
  }



  /**
   * Extracts the DN of an entry to delete from the provided buffer and tries
   * to delete it.  The buffer may contain one of three things:
   * <UL>
   *   <LI>The bare string representation of a DN.</LI>
   *   <LI>The string "dn:" followed by an optional space and the bare string
   *       representation of a DN.</LI>
   *   <LI>The string "dn::" followed by an optional space and the
   *       base64-encoded representation of a DN.</LI>
   * </UL>
   *
   * @param  returnCode  A reference that should be updated with the result code
   *                     from the first failure that is encountered.  It must
   *                     not be {@code null}, but may be unset.
   * @param  rawString   The string representation of the DN to delete.
   *
   * @return  {@code true} if the buffer was empty or if it contained the DN of
   *          an entry that was successfully deleted, or {@code false} if an
   *          error occurred while extracting the DN or attempting to delete the
   *          target entry.
   */
  private boolean deleteDNFromInputStream(
                       @NotNull final AtomicReference<ResultCode> returnCode,
                       @NotNull final String rawString)
  {
    final String lowerString = StaticUtils.toLowerCase(rawString);
    if (lowerString.startsWith("dn::"))
    {
      final String base64EncodedDN = rawString.substring(4).trim();
      if (base64EncodedDN.isEmpty())
      {
        returnCode.compareAndSet(null, ResultCode.PARAM_ERROR);
        commentToErr(ERR_LDAPDELETE_BASE64_DN_EMPTY.get(rawString));
        return false;
      }

      final String base64DecodedDN;
      try
      {
        base64DecodedDN = Base64.decodeToString(base64EncodedDN);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        returnCode.compareAndSet(null, ResultCode.PARAM_ERROR);
        commentToErr(ERR_LDAPDELETE_BASE64_DN_NOT_BASE64.get(rawString));
        return false;
      }

      return deleteEntry(base64DecodedDN, returnCode);
    }
    else if (lowerString.startsWith("dn:"))
    {
      final String dn = rawString.substring(3).trim();
      if (dn.isEmpty())
      {
        returnCode.compareAndSet(null, ResultCode.PARAM_ERROR);
        commentToErr(ERR_LDAPDELETE_DN_EMPTY.get(rawString));
        return false;
      }

      return deleteEntry(dn, returnCode);
    }
    else
    {
      return deleteEntry(rawString, returnCode);
    }
  }



  /**
   * Creates a buffered reader that can read data from the provided input stream
   * using the specified character set.  The data to be read may optionally be
   * passphrase-encrypted and/or gzip-compressed.
   *
   * @param  inputStream           The input stream from which the data is to be
   *                               read.
   * @param  charset               The character set to use when reading the
   *                               data from the input stream.  It must not be
   *                               {@code null}.
   * @param  potentialPassphrases  A list of the potential passphrases that may
   *                               be used to decrypt data read from the
   *                               provided input stream.  It must not be
   *                               {@code null}, and must be updatable, but may
   *                               be empty.
   *
   * @return  The buffered reader that can be used to read data from the
   *          provided input stream.
   *
   * @throws  IOException  If an error occurs while trying to read data from the
   *                       input stream or create the buffered reader.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    attempting to interact with encrypted
   *                                    data read from the input stream.
   */
  @NotNull()
  private BufferedReader getBufferedReader(
               @NotNull final InputStream inputStream,
               @NotNull final Charset charset,
               @NotNull final List<char[]> potentialPassphrases)
          throws IOException, GeneralSecurityException
  {
    // Check to see if the input stream is encrypted.  If so, then get access to
    // a decrypted representation of its contents.
    final ObjectPair<InputStream,char[]> decryptedInputStreamData =
         ToolUtils.getPossiblyPassphraseEncryptedInputStream(inputStream,
              potentialPassphrases, (! encryptionPassphraseFile.isPresent()),
              INFO_LDAPDELETE_ENCRYPTION_PASSPHRASE_PROMPT.get(),
              ERR_LDAPDELETE_ENCRYPTION_PASSPHRASE_ERROR.get(), getOut(),
              getErr());
    final InputStream decryptedInputStream =
         decryptedInputStreamData.getFirst();
    final char[] passphrase = decryptedInputStreamData.getSecond();
    if (passphrase != null)
    {
      boolean isExistingPassphrase = false;
      for (final char[] existingPassphrase : potentialPassphrases)
      {
        if (Arrays.equals(passphrase, existingPassphrase))
        {
          isExistingPassphrase = true;
          break;
        }
      }

      if (! isExistingPassphrase)
      {
        potentialPassphrases.add(passphrase);
      }
    }


    // Check to see if the input stream is compressed.
    final InputStream decompressedInputStream =
         ToolUtils.getPossiblyGZIPCompressedInputStream(decryptedInputStream);


    // Get an input stream reader that uses the specified character set, and
    // then wrap that with a buffered reader.
    final InputStreamReader inputStreamReader =
         new InputStreamReader(decompressedInputStream, charset);
    return new BufferedReader(inputStreamReader);
  }



  /**
   * Deletes entries that match filters specified in the
   * deleteEntriesMatchingFilter argument.
   *
   * @param  returnCode  A reference that should be updated with the result code
   *                     from the first failure that is encountered.  It must
   *                     not be {@code null}, but may be unset.
   */
  private void deleteFromFilters(
                    @NotNull final AtomicReference<ResultCode> returnCode)
  {
    for (final Filter f : deleteEntriesMatchingFilter.getValues())
    {
      if ((! searchAndDelete(f.toString(), returnCode)) &&
           (! continueOnError.isPresent()))
      {
        return;
      }
    }
  }



  /**
   * Deletes entries that match filters specified in the
   * deleteEntriesMatchingFilterFromFile argument.
   *
   * @param  returnCode            A reference that should be updated with the
   *                               result code from the first failure that is
   *                               encountered.  It must not be {@code null},
   *                               but may be unset.
   * @param  charset               The character set to use when reading the
   *                               data from the file.  It must not be
   *                               {@code null}.
   * @param  encryptionPassphrase  The passphrase to use to decrypt the data
   *                               read from the file if it happens to be
   *                               encrypted.  This may be {@code null} if the
   *                               user should be interactively prompted for the
   *                               passphrase if a file happens to be encrypted.
   */
  private void deleteFromFilterFile(
                    @NotNull final AtomicReference<ResultCode> returnCode,
                    @NotNull final Charset charset,
                    @Nullable final char[] encryptionPassphrase)
  {
    final List<char[]> potentialPassphrases =
         new ArrayList<>(dnFile.getValues().size());
    if (encryptionPassphrase != null)
    {
      potentialPassphrases.add(encryptionPassphrase);
    }

    for (final File f : deleteEntriesMatchingFiltersFromFile.getValues())
    {
      if (verbose.isPresent())
      {
        commentToOut(INFO_LDAPDELETE_READING_FILTERS_FROM_FILE.get(
             f.getAbsolutePath()));
        out();
      }

      try (FileInputStream fis = new FileInputStream(f);
           BufferedReader reader =
                getBufferedReader(fis, charset, potentialPassphrases))
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

          if ((! searchAndDelete(line, returnCode)) &&
               (! continueOnError.isPresent()))
          {
            return;
          }
        }
      }
      catch (final IOException | GeneralSecurityException e)
      {
        commentToErr(ERR_LDAPDELETE_ERROR_READING_FILTER_FILE.get(
             f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
        if (! continueOnError.isPresent())
        {
          return;
        }
      }
    }
  }




  /**
   * Issues a search with the provided filter and attempts to delete all
   * matching entries.
   *
   * @param  filterString  The string representation of the filter to use when
   *                       processing the search.  It must not be {@code null}.
   * @param  returnCode    A reference that should be updated with the result
   *                       code from the first failure that is encountered.  It
   *                       must not be {@code null}, but may be unset.
   *
   * @return  {@code true} if the search and all deletes were processed
   *          successfully, or {@code false} if any problems were encountered.
   */
  private boolean searchAndDelete(@NotNull final String filterString,
                       @NotNull final AtomicReference<ResultCode> returnCode)
  {
    boolean successful = true;
    final AtomicLong entriesDeleted = new AtomicLong(0L);
    for (final DN baseDN : searchBaseDN.getValues())
    {
      if (searchPageSize.isPresent())
      {
        successful &= doPagedSearchAndDelete(baseDN.toString(), filterString,
             returnCode, entriesDeleted);
      }
      else
      {
        successful &= doNonPagedSearchAndDelete(baseDN.toString(), filterString,
             returnCode, entriesDeleted);
      }
    }

    if (successful && (entriesDeleted.get() == 0))
    {
      commentToErr(ERR_LDAPDELETE_SEARCH_RETURNED_NO_ENTRIES.get(filterString));
      returnCode.compareAndSet(null, ResultCode.NO_RESULTS_RETURNED);
      successful = false;
    }

    return successful;
  }



  /**
   * Issues the provided search using the simple paged results control and
   * attempts to delete all of the matching entries.
   *
   * @param  baseDN          The base DN for the search request.  It must not
   *                         be {@code null}.
   * @param  filterString    The string representation of the filter ot use for
   *                         the search request.  It must not be {@code null}.
   * @param  returnCode      A reference that should be updated with the result
   *                         code from the first failure that is encountered.
   *                         It must not be {@code null}, but may be unset.
   * @param  entriesDeleted  A counter that will be updated for each entry that
   *                         is successfully deleted.  It must not be
   *                         {@code null}.
   *
   * @return  {@code true} if all entries matching the search criteria were
   *          successfully deleted (even if there were no matching entries), or
   *          {@code false} if an error occurred while attempting to process a
   *          search or delete operation.
   */
  private boolean doPagedSearchAndDelete(@NotNull final String baseDN,
                       @NotNull final String filterString,
                       @NotNull final AtomicReference<ResultCode> returnCode,
                       @NotNull final AtomicLong entriesDeleted)
  {
    ASN1OctetString cookie = null;
    final TreeSet<DN> matchingEntryDNs = new TreeSet<>();
    final LDAPDeleteSearchListener searchListener =
         new LDAPDeleteSearchListener(this, matchingEntryDNs, baseDN,
              filterString, returnCode);
    while (true)
    {
      try
      {
        final ArrayList<Control> requestControls = new ArrayList<>(10);
        requestControls.addAll(searchControls);
        requestControls.add(new SimplePagedResultsControl(
             searchPageSize.getValue(), cookie, true));

        final SearchRequest searchRequest = new SearchRequest(searchListener,
             baseDN, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0, false,
             filterString, SearchRequest.NO_ATTRIBUTES);
        searchRequest.setControls(requestControls);

        if (verbose.isPresent())
        {
          commentToOut(INFO_LDAPDELETE_ISSUING_SEARCH_REQUEST.get(
               String.valueOf(searchRequest)));
        }

        final SearchResult searchResult = connectionPool.search(searchRequest);

        if (verbose.isPresent())
        {
          commentToOut(INFO_LDAPDELETE_RECEIVED_SEARCH_RESULT.get(
               String.valueOf(searchResult)));
        }

        final SimplePagedResultsControl responseControl =
             SimplePagedResultsControl.get(searchResult);
        if (responseControl == null)
        {
          throw new LDAPException(ResultCode.CONTROL_NOT_FOUND,
               ERR_LDAPDELETE_MISSING_PAGED_RESULTS_RESPONSE.get(searchResult));
        }
        else if (responseControl.moreResultsToReturn())
        {
          cookie = responseControl.getCookie();
        }
        else
        {
          break;
        }
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        returnCode.compareAndSet(null, e.getResultCode());
        commentToErr(ERR_LDAPDELETE_SEARCH_ERROR.get(baseDN, filterString,
             String.valueOf(e.getResultCode()), e.getMessage()));
      }
    }

    boolean allSuccessful = true;
    final Iterator<DN> iterator = matchingEntryDNs.descendingIterator();
    while (iterator.hasNext())
    {
      if (deleteEntry(iterator.next().toString(), returnCode))
      {
        entriesDeleted.incrementAndGet();
      }
      else
      {
        allSuccessful = false;
        if (! continueOnError.isPresent())
        {
          break;
        }
      }
    }

    return allSuccessful;
  }



  /**
   * Issues the provided search (without using the simple paged results control)
   * and attempts to delete all of the matching entries.
   *
   * @param  baseDN          The base DN for the search request.  It must not
   *                         be {@code null}.
   * @param  filterString    The string representation of the filter ot use for
   *                         the search request.  It must not be {@code null}.
   * @param  returnCode      A reference that should be updated with the result
   *                         code from the first failure that is encountered.
   *                         It must not be {@code null}, but may be unset.
   * @param  entriesDeleted  A counter that will be updated for each entry that
   *                         is successfully deleted.  It must not be
   *                         {@code null}.
   *
   * @return  {@code true} if all entries matching the search criteria were
   *          successfully deleted (even if there were no matching entries), or
   *          {@code false} if an error occurred while attempting to process a
   *          search or delete operation.
   */
  private boolean doNonPagedSearchAndDelete(@NotNull final String baseDN,
                       @NotNull final String filterString,
                       @NotNull final AtomicReference<ResultCode> returnCode,
                       @NotNull final AtomicLong entriesDeleted)
  {
    final TreeSet<DN> matchingEntryDNs = new TreeSet<>();
    final LDAPDeleteSearchListener searchListener =
         new LDAPDeleteSearchListener(this, matchingEntryDNs, baseDN,
              filterString, returnCode);
    try
    {
      final SearchRequest searchRequest = new SearchRequest(searchListener,
           baseDN, SearchScope.SUB, DereferencePolicy.NEVER, 0, 0, false,
           filterString, SearchRequest.NO_ATTRIBUTES);
      searchRequest.setControls(searchControls);

      if (verbose.isPresent())
      {
        commentToOut(INFO_LDAPDELETE_ISSUING_SEARCH_REQUEST.get(
             String.valueOf(searchRequest)));
      }

      final SearchResult searchResult = connectionPool.search(searchRequest);

      if (verbose.isPresent())
      {
        commentToOut(INFO_LDAPDELETE_RECEIVED_SEARCH_RESULT.get(
             String.valueOf(searchResult)));
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      returnCode.compareAndSet(null, e.getResultCode());
      commentToErr(ERR_LDAPDELETE_SEARCH_ERROR.get(baseDN, filterString,
           String.valueOf(e.getResultCode()), e.getMessage()));
    }


    boolean allSuccessful = true;
    final Iterator<DN> iterator = matchingEntryDNs.descendingIterator();
    while (iterator.hasNext())
    {
      if (deleteEntry(iterator.next().toString(), returnCode))
      {
        entriesDeleted.incrementAndGet();
      }
      else
      {
        allSuccessful = false;
        if (! continueOnError.isPresent())
        {
          break;
        }
      }
    }

    return allSuccessful;
  }



  /**
   * Deletes entries whose DNs are specified as trailing arguments.
   *
   * @param  returnCode  A reference that should be updated with the result code
   *                     from the first failure that is encountered.  It must
   *                     not be {@code null}, but may be unset.
   */
  private void deleteFromTrailingArguments(
                    @NotNull final AtomicReference<ResultCode> returnCode)
  {
    for (final String dn : parser.getTrailingArguments())
    {
      if ((! deleteEntry(dn, returnCode)) && (! continueOnError.isPresent()))
      {
        return;
      }
    }
  }



  /**
   * Deletes entries whose DNs are read from standard input.
   *
   * @param  returnCode            A reference that should be updated with the
   *                               result code from the first failure that is
   *                               encountered.  It must not be {@code null},
   *                               but may be unset.
   * @param  charset               The character set to use when reading the
   *                               data from standard input.  It must not be
   *                               {@code null}.
   * @param  encryptionPassphrase  The passphrase to use to decrypt the data
   *                               read from standard input if it happens to be
   *                               encrypted.  This may be {@code null} if the
   *                               user should be interactively prompted for the
   *                               passphrase if the data happens to be
   *                               encrypted.
   */
  private void deleteFromStandardInput(
                    @NotNull final AtomicReference<ResultCode> returnCode,
                    @NotNull final Charset charset,
                    @Nullable final char[] encryptionPassphrase)
  {
    final List<char[]> potentialPassphrases = new ArrayList<>(1);
    if (encryptionPassphrase != null)
    {
      potentialPassphrases.add(encryptionPassphrase);
    }

    commentToOut(INFO_LDAPDELETE_READING_FROM_STDIN.get());
    out();

    try
    {
      deleteDNsFromInputStream(returnCode, in, charset, potentialPassphrases);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      returnCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
      commentToErr(ERR_LDAPDELETE_ERROR_READING_STDIN.get(
           StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Attempts to delete the specified entry.
   *
   * @param  dn          The DN of the entry to delete.  It must not be
   *                     {@code null}.
   * @param  returnCode  A reference to the result code to be returned.  It must
   *                     not be {@code null}, but may be unset.  If it is unset
   *                     and the delete attempt fails, then this should be set
   *                     to the result code for the failed delete operation.
   *
   * @return  {@code true} if the entry was successfully deleted, or
   *          {@code false} if not.
   */
  private boolean deleteEntry(@NotNull final String dn,
               @NotNull final AtomicReference<ResultCode> returnCode)
  {
    // Display a message indicating that we're going to delete the entry.
    if (subtreeDeleter == null)
    {
      commentToOut(INFO_LDAPDELETE_DELETING_ENTRY.get(dn));
    }
    else
    {
      commentToOut(INFO_LDAPDELETE_CLIENT_SIDE_SUBTREE_DELETING.get(dn));
    }


    // If the --dryRun argument was provided, then don't actually delete the
    // entry.  Just pretend that it succeeded.
    if (dryRun.isPresent())
    {
      commentToOut(INFO_LDAPDELETE_NOT_DELETING_BECAUSE_OF_DRY_RUN.get(dn));
      return true;
    }

    if (subtreeDeleter == null)
    {
      // If we need to rate limit the delete operations, then do that now.
      if (deleteRateLimiter != null)
      {
        deleteRateLimiter.await();
      }


      // Create and process the delete request.
      final DeleteRequest deleteRequest = new DeleteRequest(dn);
      deleteRequest.setControls(deleteControls);

      boolean successlful;
      LDAPResult deleteResult;
      try
      {
        if (verbose.isPresent())
        {
          commentToOut(INFO_LDAPDELETE_SENDING_DELETE_REQUEST.get(
               String.valueOf(deleteRequest)));
        }

        deleteResult = connectionPool.delete(deleteRequest);
        successlful = true;
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        deleteResult = e.toLDAPResult();
        successlful = false;
      }


      // Display information about the result.
      for (final String resultLine :
           ResultUtils.formatResult(deleteResult, true, 0, WRAP_COLUMN))
      {
        if (successlful)
        {
          out(resultLine);
        }
        else
        {
          err(resultLine);
        }
      }


      // If the delete attempt failed, then update the return code and/or
      // write to the reject writer, if appropriate.
      final ResultCode deleteResultCode = deleteResult.getResultCode();
      if ((deleteResultCode != ResultCode.SUCCESS) &&
         (deleteResultCode != ResultCode.NO_OPERATION))
      {
        returnCode.compareAndSet(null, deleteResultCode);
        writeToRejects(deleteRequest, deleteResult);
        err();
        return false;
      }
      else
      {
        out();
        return true;
      }
    }
    else
    {
      // Use the subtree deleter to attempt a client-side subtree delete.
      final SubtreeDeleterResult subtreeDeleterResult;
      try
      {
        subtreeDeleterResult = subtreeDeleter.delete(connectionPool, dn);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        commentToErr(e.getMessage());
        writeToRejects(new DeleteRequest(dn), e.toLDAPResult());
        returnCode.compareAndSet(null, e.getResultCode());
        return false;
      }

      if (subtreeDeleterResult.completelySuccessful())
      {
        final long entriesDeleted = subtreeDeleterResult.getEntriesDeleted();
        if (entriesDeleted == 0L)
        {
          final DeleteRequest deleteRequest = new DeleteRequest(dn);
          final LDAPResult result = new LDAPResult(-1,
               ResultCode.NO_SUCH_OBJECT,
               ERR_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_NO_BASE_ENTRY.get(dn),
               null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
          for (final String line :
               ResultUtils.formatResult(result, true, 0, WRAP_COLUMN))
          {
            err(line);
          }
          writeToRejects(deleteRequest, result);
          returnCode.compareAndSet(null, ResultCode.NO_SUCH_OBJECT);
          err();
          return false;
        }
        else if (entriesDeleted == 1L)
        {
          commentToOut(
               INFO_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_ONLY_BASE.get(dn));
          out();
          return true;
        }
        else
        {
          final long numSubordinates = entriesDeleted - 1L;
          commentToOut(INFO_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_WITH_SUBS.get(dn,
               numSubordinates));
          out();
          return true;
        }
      }
      else
      {
        commentToErr(ERR_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_FAILED.get());
        err();

        final SearchResult searchError = subtreeDeleterResult.getSearchError();
        if (searchError != null)
        {
          returnCode.compareAndSet(null, searchError.getResultCode());
          commentToErr(
               ERR_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_SEARCH_ERROR.get(dn));
          for (final String line :
            ResultUtils.formatResult(searchError, true, 0, WRAP_COLUMN))
          {
            err(line);
          }
          err();
        }

        for (final Map.Entry<DN,LDAPResult> deleteError :
             subtreeDeleterResult.getDeleteErrorsDescendingMap().entrySet())
        {
          final String failureDN = deleteError.getKey().toString();
          final LDAPResult failureResult = deleteError.getValue();
          returnCode.compareAndSet(null, failureResult.getResultCode());
          commentToErr(ERR_LDAPDELETE_CLIENT_SIDE_SUBTREE_DEL_DEL_ERROR.get(
               failureDN, dn));
          writeToRejects(new DeleteRequest(failureDN), failureResult);
          for (final String line :
            ResultUtils.formatResult(failureResult, true, 0, WRAP_COLUMN))
          {
            err(line);
          }
          err();
        }

        return false;
      }
    }
  }



  /**
   * Writes information about a failed operation to the reject writer.  If an
   * error occurs while writing the rejected change, then that error will be
   * written to standard error.
   *
   * @param  deleteRequest  The delete request that failed.
   * @param  deleteResult   The result for the failed delete.
   */
  private void writeToRejects(@NotNull final DeleteRequest deleteRequest,
                              @NotNull final LDAPResult deleteResult)
  {
    if (! rejectFile.isPresent())
    {
      return;
    }

    LDIFWriter w;
    try
    {
      w = rejectWriter.get();
      if (w == null)
      {
        w = new LDIFWriter(rejectFile.getValue());
        rejectWriter.set(w);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      commentToErr(ERR_LDAPDELETE_WRITE_TO_REJECTS_FAILED.get(
           StaticUtils.getExceptionMessage(e)));
      return;
    }

    try
    {
      boolean firstLine = true;
      for (final String commentLine :
           ResultUtils.formatResult(deleteResult, false, 0, (WRAP_COLUMN - 2)))
      {
        w.writeComment(commentLine, firstLine, false);
        firstLine = false;
      }
      w.writeChangeRecord(deleteRequest.toLDIFChangeRecord());
      w.flush();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      commentToErr(ERR_LDAPDELETE_WRITE_TO_REJECTS_FAILED.get(
           StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Retrieves the set of controls that should be included in delete requests.
   *
   * @return  The set of controls that should be included in delete requests.
   */
  @NotNull()
  private List<Control> getDeleteControls()
  {
    final List<Control> controlList = new ArrayList<>(10);

    if (deleteControl.isPresent())
    {
      controlList.addAll(deleteControl.getValues());
    }

    controlList.addAll(routeToBackendSetRequestControls);

    if (serverSideSubtreeDelete.isPresent())
    {
      controlList.add(new SubtreeDeleteRequestControl(true));
    }

    if (softDelete.isPresent())
    {
      controlList.add(new SoftDeleteRequestControl(true, true));
    }

    if (hardDelete.isPresent() && (! clientSideSubtreeDelete.isPresent()))
    {
      controlList.add(new HardDeleteRequestControl(true));
    }

    if (proxyAs.isPresent())
    {
      controlList.add(
           new ProxiedAuthorizationV2RequestControl(proxyAs.getValue()));
    }

    if (proxyV1As.isPresent())
    {
      controlList.add(new ProxiedAuthorizationV1RequestControl(
           proxyV1As.getValue().toString()));
    }

    if (manageDsaIT.isPresent() && (! clientSideSubtreeDelete.isPresent()))
    {
      controlList.add(new ManageDsaITRequestControl(true));
    }

    if (assertionFilter.isPresent())
    {
      controlList.add(
           new AssertionRequestControl(assertionFilter.getValue(), true));
    }

    if (preReadAttribute.isPresent())
    {
      controlList.add(new PreReadRequestControl(true,
           preReadAttribute.getValues().toArray(StaticUtils.NO_STRINGS)));
    }

    if (noOperation.isPresent())
    {
      controlList.add(new NoOpRequestControl());
    }

    if (getBackendSetID.isPresent())
    {
      controlList.add(new GetBackendSetIDRequestControl(true));
    }

    if (getServerID.isPresent())
    {
      controlList.add(new GetServerIDRequestControl(true));
    }

    if (routeToServer.isPresent())
    {
      controlList.add(new RouteToServerRequestControl(true,
           routeToServer.getValue(), false, false, false));
    }

    if (useAssuredReplication.isPresent())
    {
      AssuredReplicationLocalLevel localLevel = null;
      if (assuredReplicationLocalLevel.isPresent())
      {
        final String level = assuredReplicationLocalLevel.getValue();
        if (level.equalsIgnoreCase("none"))
        {
          localLevel = AssuredReplicationLocalLevel.NONE;
        }
        else if (level.equalsIgnoreCase("received-any-server"))
        {
          localLevel = AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER;
        }
        else if (level.equalsIgnoreCase("processed-all-servers"))
        {
          localLevel = AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS;
        }
      }

      AssuredReplicationRemoteLevel remoteLevel = null;
      if (assuredReplicationRemoteLevel.isPresent())
      {
        final String level = assuredReplicationRemoteLevel.getValue();
        if (level.equalsIgnoreCase("none"))
        {
          remoteLevel = AssuredReplicationRemoteLevel.NONE;
        }
        else if (level.equalsIgnoreCase("received-any-remote-location"))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION;
        }
        else if (level.equalsIgnoreCase("received-all-remote-locations"))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS;
        }
        else if (level.equalsIgnoreCase("processed-all-remote-servers"))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS;
        }
      }

      Long timeoutMillis = null;
      if (assuredReplicationTimeout.isPresent())
      {
        timeoutMillis =
             assuredReplicationTimeout.getValue(TimeUnit.MILLISECONDS);
      }

      final AssuredReplicationRequestControl c =
           new AssuredReplicationRequestControl(true, localLevel, localLevel,
                remoteLevel, remoteLevel, timeoutMillis, false);
      controlList.add(c);
    }

    if (replicationRepair.isPresent())
    {
      controlList.add(new ReplicationRepairRequestControl());
    }

    if (suppressReferentialIntegrityUpdates.isPresent())
    {
      controlList.add(
           new SuppressReferentialIntegrityUpdatesRequestControl(true));
    }

    if (operationPurpose.isPresent())
    {
      controlList.add(new OperationPurposeRequestControl(true,
           "ldapdelete", Version.NUMERIC_VERSION_STRING,
           LDAPDelete.class.getName() + ".getDeleteControls",
           operationPurpose.getValue()));
    }

    return Collections.unmodifiableList(controlList);
  }



  /**
   * Retrieves the set of controls that should be included in search requests.
   *
   * @return  The set of controls that should be included in delete requests.
   */
  @NotNull()
  private List<Control> getSearchControls()
  {
    final List<Control> controlList = new ArrayList<>(10);

    controlList.addAll(routeToBackendSetRequestControls);

    if (manageDsaIT.isPresent())
    {
      controlList.add(new ManageDsaITRequestControl(true));
    }

    if (proxyV1As.isPresent())
    {
      controlList.add(new ProxiedAuthorizationV1RequestControl(
           proxyV1As.getValue().toString()));
    }

    if (proxyAs.isPresent())
    {
      controlList.add(
           new ProxiedAuthorizationV2RequestControl(proxyAs.getValue()));
    }

    if (operationPurpose.isPresent())
    {
      controlList.add(new OperationPurposeRequestControl(true,
           "ldapdelete", Version.NUMERIC_VERSION_STRING,
           LDAPDelete.class.getName() + ".getSearchControls",
           operationPurpose.getValue()));
    }

    if (routeToServer.isPresent())
    {
      controlList.add(new RouteToServerRequestControl(true,
           routeToServer.getValue(), false, false, false));
    }

    return Collections.unmodifiableList(controlList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    ResultUtils.formatUnsolicitedNotification(lines, notification, true, 0,
         WRAP_COLUMN);
    for (final String line : lines)
    {
      err(line);
    }
    err();
  }



  /**
   * Writes a line-wrapped, commented version of the provided message to
   * standard output.
   *
   * @param  message  The message to be written.
   */
  void commentToOut(@NotNull final String message)
  {
    for (final String line : StaticUtils.wrapLine(message, WRAP_COLUMN - 2))
    {
      out("# ", line);
    }
  }



  /**
   * Writes a line-wrapped, commented version of the provided message to
   * standard error.
   *
   * @param  message  The message to be written.
   */
  void commentToErr(@NotNull final String message)
  {
    for (final String line : StaticUtils.wrapLine(message, WRAP_COLUMN - 2))
    {
      err("# ", line);
    }
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
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "uid=test.user,ou=People,dc=example,dc=com"
         },
         INFO_LDAPDELETE_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--trustStorePath", "trust-store.jks",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--bindPasswordFile", "admin-password.txt",
           "--dnFile", "dns-to-delete.txt"
         },
         INFO_LDAPDELETE_EXAMPLE_2.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "389",
           "--useStartTLS",
           "--trustStorePath", "trust-store.jks",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--bindPasswordFile", "admin-password.txt",
           "--deleteEntriesMatchingFilter", "(description=delete)"
         },
         INFO_LDAPDELETE_EXAMPLE_3.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "389",
           "--bindDN", "uid=admin,dc=example,dc=com"
         },
         INFO_LDAPDELETE_EXAMPLE_4.get());

    return examples;
  }
}
