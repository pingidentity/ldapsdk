/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.MatchedValuesFilter;
import com.unboundid.ldap.sdk.controls.MatchedValuesRequestControl;
import com.unboundid.ldap.sdk.controls.PersistentSearchChangeType;
import com.unboundid.ldap.sdk.controls.PersistentSearchRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.RFC3672SubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;
import com.unboundid.ldap.sdk.persist.PersistUtils;
import com.unboundid.ldap.sdk.transformations.EntryTransformation;
import com.unboundid.ldap.sdk.transformations.ExcludeAttributeTransformation;
import com.unboundid.ldap.sdk.transformations.MoveSubtreeTransformation;
import com.unboundid.ldap.sdk.transformations.RedactAttributeTransformation;
import com.unboundid.ldap.sdk.transformations.RenameAttributeTransformation;
import com.unboundid.ldap.sdk.transformations.ScrambleAttributeTransformation;
import com.unboundid.ldap.sdk.unboundidds.controls.AccountUsableRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.ExcludeBranchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetBackendSetIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetEffectiveRightsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetRecentLoginHistoryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinBaseDN;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRequestValue;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRule;
import com.unboundid.ldap.sdk.unboundidds.controls.
            MatchingEntryCountRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OverrideSearchLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PermitUnindexedSearchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RealAttributesOnlyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RejectUnindexedSearchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReturnConflictEntriesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RouteToBackendSetRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RouteToServerRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SoftDeletedEntryAccessRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressOperationalAttributeUpdateRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SuppressType;
import com.unboundid.ldap.sdk.unboundidds.controls.
            VirtualAttributesOnlyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionPostConnectProcessor;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.FilterFileReader;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TeeOutputStream;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of an LDAP command-line tool that may
 * be used to issue searches to a directory server.  Matching entries will be
 * output in the LDAP data interchange format (LDIF), to standard output and/or
 * to a specified file.  This is a much more full-featured tool than the
 * {@link com.unboundid.ldap.sdk.examples.LDAPSearch} tool, and includes a
 * number of features only intended for use with Ping Identity, UnboundID, and
 * Nokia/Alcatel-Lucent 8661 server products.
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
public final class LDAPSearch
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which to wrap long lines.
   */
  private static int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // The set of arguments supported by this program.
  @Nullable private BooleanArgument accountUsable = null;
  @Nullable private BooleanArgument authorizationIdentity = null;
  @Nullable private BooleanArgument compressOutput = null;
  @Nullable private BooleanArgument continueOnError = null;
  @Nullable private BooleanArgument countEntries = null;
  @Nullable private BooleanArgument dontWrap = null;
  @Nullable private BooleanArgument draftLDUPSubentries = null;
  @Nullable private BooleanArgument dryRun = null;
  @Nullable private BooleanArgument encryptOutput = null;
  @Nullable private BooleanArgument followReferrals = null;
  @Nullable private BooleanArgument getBackendSetID = null;
  @Nullable private BooleanArgument getServerID = null;
  @Nullable private BooleanArgument getRecentLoginHistory = null;
  @Nullable private BooleanArgument hideRedactedValueCount = null;
  @Nullable private BooleanArgument getUserResourceLimits = null;
  @Nullable private BooleanArgument includeReplicationConflictEntries = null;
  @Nullable private BooleanArgument joinRequireMatch = null;
  @Nullable private BooleanArgument manageDsaIT = null;
  @Nullable private BooleanArgument permitUnindexedSearch = null;
  @Nullable private BooleanArgument realAttributesOnly = null;
  @Nullable private BooleanArgument rejectUnindexedSearch = null;
  @Nullable private BooleanArgument requireMatch = null;
  @Nullable private BooleanArgument retryFailedOperations = null;
  @Nullable private BooleanArgument separateOutputFilePerSearch = null;
  @Nullable private BooleanArgument suppressBase64EncodedValueComments = null;
  @Nullable private BooleanArgument teeResultsToStandardOut = null;
  @Nullable private BooleanArgument useAdministrativeSession = null;
  @Nullable private BooleanArgument usePasswordPolicyControl = null;
  @Nullable private BooleanArgument terse = null;
  @Nullable private BooleanArgument typesOnly = null;
  @Nullable private BooleanArgument verbose = null;
  @Nullable private BooleanArgument virtualAttributesOnly = null;
  @Nullable private BooleanValueArgument rfc3672Subentries = null;
  @Nullable private ControlArgument bindControl = null;
  @Nullable private ControlArgument searchControl = null;
  @Nullable private DNArgument baseDN = null;
  @Nullable private DNArgument excludeBranch = null;
  @Nullable private DNArgument moveSubtreeFrom = null;
  @Nullable private DNArgument moveSubtreeTo = null;
  @Nullable private DNArgument proxyV1As = null;
  @Nullable private FileArgument encryptionPassphraseFile = null;
  @Nullable private FileArgument filterFile = null;
  @Nullable private FileArgument ldapURLFile = null;
  @Nullable private FileArgument outputFile = null;
  @Nullable private FilterArgument assertionFilter = null;
  @Nullable private FilterArgument filter = null;
  @Nullable private FilterArgument joinFilter = null;
  @Nullable private FilterArgument matchedValuesFilter = null;
  @Nullable private IntegerArgument joinSizeLimit = null;
  @Nullable private IntegerArgument ratePerSecond = null;
  @Nullable private IntegerArgument scrambleRandomSeed = null;
  @Nullable private IntegerArgument simplePageSize = null;
  @Nullable private IntegerArgument sizeLimit = null;
  @Nullable private IntegerArgument timeLimitSeconds = null;
  @Nullable private IntegerArgument wrapColumn = null;
  @Nullable private ScopeArgument joinScope = null;
  @Nullable private ScopeArgument scope = null;
  @Nullable private StringArgument dereferencePolicy = null;
  @Nullable private StringArgument excludeAttribute = null;
  @Nullable private StringArgument getAuthorizationEntryAttribute = null;
  @Nullable private StringArgument getEffectiveRightsAttribute = null;
  @Nullable private StringArgument getEffectiveRightsAuthzID = null;
  @Nullable private StringArgument includeSoftDeletedEntries = null;
  @Nullable private StringArgument joinBaseDN = null;
  @Nullable private StringArgument joinRequestedAttribute = null;
  @Nullable private StringArgument joinRule = null;
  @Nullable private StringArgument matchingEntryCountControl = null;
  @Nullable private StringArgument operationPurpose = null;
  @Nullable private StringArgument outputFormat = null;
  @Nullable private StringArgument overrideSearchLimit = null;
  @Nullable private StringArgument persistentSearch = null;
  @Nullable private StringArgument proxyAs = null;
  @Nullable private StringArgument redactAttribute = null;
  @Nullable private StringArgument renameAttributeFrom = null;
  @Nullable private StringArgument renameAttributeTo = null;
  @Nullable private StringArgument requestedAttribute = null;
  @Nullable private StringArgument routeToBackendSet = null;
  @Nullable private StringArgument routeToServer = null;
  @Nullable private StringArgument scrambleAttribute = null;
  @Nullable private StringArgument scrambleJSONField = null;
  @Nullable private StringArgument sortOrder = null;
  @Nullable private StringArgument suppressOperationalAttributeUpdates = null;
  @Nullable private StringArgument virtualListView = null;

  // The argument parser used by this tool.
  @Nullable private volatile ArgumentParser parser = null;

  // Controls that should be sent to the server but need special validation.
  @Nullable private volatile JoinRequestControl joinRequestControl = null;
  @NotNull private final List<RouteToBackendSetRequestControl>
       routeToBackendSetRequestControls = new ArrayList<>(10);
  @Nullable private volatile MatchedValuesRequestControl
       matchedValuesRequestControl = null;
  @Nullable private volatile MatchingEntryCountRequestControl
       matchingEntryCountRequestControl = null;
  @Nullable private volatile OverrideSearchLimitsRequestControl
       overrideSearchLimitsRequestControl = null;
  @Nullable private volatile PersistentSearchRequestControl
       persistentSearchRequestControl = null;
  @Nullable private volatile ServerSideSortRequestControl sortRequestControl =
       null;
  @Nullable private volatile VirtualListViewRequestControl vlvRequestControl =
       null;

  // Other values decoded from arguments.
  @Nullable private volatile DereferencePolicy derefPolicy = null;

  // The print streams used for standard output and error.
  @NotNull private final AtomicLong outputFileCounter = new AtomicLong(1);
  @Nullable private volatile PrintStream errStream = null;
  @Nullable private volatile PrintStream outStream = null;

  // The output handler for this tool.
  @NotNull private volatile LDAPSearchOutputHandler outputHandler =
       new LDIFLDAPSearchOutputHandler(this, WRAP_COLUMN);

  // The list of entry transformations to apply.
  @Nullable private volatile List<EntryTransformation> entryTransformations =
       null;

  // The encryption passphrase to use if the output is to be encrypted.
  @Nullable private String encryptionPassphrase = null;



  /**
   * Runs this tool with the provided command-line arguments.  It will use the
   * JVM-default streams for standard input, output, and error.
   *
   * @param  args  The command-line arguments to provide to this program.
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
   * Runs this tool with the provided streams and command-line arguments.
   *
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
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDAPSearch tool = new LDAPSearch(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided streams.
   *
   * @param  out  The output stream to use for standard output.  If this is
   *              {@code null}, then standard output will be suppressed.
   * @param  err  The output stream to use for standard error.  If this is
   *              {@code null}, then standard error will be suppressed.
   */
  public LDAPSearch(@Nullable final OutputStream out,
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
    return "ldapsearch";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDAPSEARCH_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Arrays.asList(
         INFO_LDAPSEARCH_ADDITIONAL_DESCRIPTION_PARAGRAPH_1.get(),
         INFO_LDAPSEARCH_ADDITIONAL_DESCRIPTION_PARAGRAPH_2.get());
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
    return INFO_LDAPSEARCH_TRAILING_ARGS_PLACEHOLDER.get();
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
  @NotNull()
  protected Set<Character> getSuppressedShortIdentifiers()
  {
    return Collections.singleton('T');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;

    baseDN = new DNArgument('b', "baseDN", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_BASE_DN.get());
    baseDN.addLongIdentifier("base-dn", true);
    baseDN.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(baseDN);

    scope = new ScopeArgument('s', "scope", false, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SCOPE.get(), SearchScope.SUB);
    scope.addLongIdentifier("searchScope", true);
    scope.addLongIdentifier("search-scope", true);
    scope.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(scope);

    sizeLimit = new IntegerArgument('z', "sizeLimit", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SIZE_LIMIT.get(), 0,
         Integer.MAX_VALUE, 0);
    sizeLimit.addLongIdentifier("size-limit", true);
    sizeLimit.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(sizeLimit);

    timeLimitSeconds = new IntegerArgument('l', "timeLimitSeconds", false, 1,
         null, INFO_LDAPSEARCH_ARG_DESCRIPTION_TIME_LIMIT.get(), 0,
         Integer.MAX_VALUE, 0);
    timeLimitSeconds.addLongIdentifier("timeLimit", true);
    timeLimitSeconds.addLongIdentifier("time-limit-seconds", true);
    timeLimitSeconds.addLongIdentifier("time-limit", true);
    timeLimitSeconds.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(timeLimitSeconds);

    final Set<String> derefAllowedValues =
         StaticUtils.setOf("never", "always", "search", "find");
    dereferencePolicy = new StringArgument('a', "dereferencePolicy", false, 1,
         "{never|always|search|find}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_DEREFERENCE_POLICY.get(),
         derefAllowedValues, "never");
    dereferencePolicy.addLongIdentifier("dereference-policy", true);
    dereferencePolicy.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(dereferencePolicy);

    typesOnly = new BooleanArgument('A', "typesOnly", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_TYPES_ONLY.get());
    typesOnly.addLongIdentifier("types-only", true);
    typesOnly.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(typesOnly);

    requestedAttribute = new StringArgument(null, "requestedAttribute", false,
         0, INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_REQUESTED_ATTR.get());
    requestedAttribute.addLongIdentifier("requested-attribute", true);
    requestedAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(requestedAttribute);

    filter = new FilterArgument(null, "filter", false, 0,
         INFO_PLACEHOLDER_FILTER.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_FILTER.get());
    filter.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(filter);

    filterFile = new FileArgument('f', "filterFile", false, 0, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_FILTER_FILE.get(), true, true,
         true, false);
    filterFile.addLongIdentifier("filename", true);
    filterFile.addLongIdentifier("filter-file", true);
    filterFile.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(filterFile);

    ldapURLFile = new FileArgument(null, "ldapURLFile", false, 0, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_LDAP_URL_FILE.get(), true, true,
         true, false);
    ldapURLFile.addLongIdentifier("ldap-url-file", true);
    ldapURLFile.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(ldapURLFile);

    followReferrals = new BooleanArgument(null, "followReferrals", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_FOLLOW_REFERRALS.get());
    followReferrals.addLongIdentifier("follow-referrals", true);
    followReferrals.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(followReferrals);

    retryFailedOperations = new BooleanArgument(null, "retryFailedOperations",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_RETRY_FAILED_OPERATIONS.get());
    retryFailedOperations.addLongIdentifier("retry-failed-operations", true);
    retryFailedOperations.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(retryFailedOperations);

    continueOnError = new BooleanArgument('c', "continueOnError", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_CONTINUE_ON_ERROR.get());
    continueOnError.addLongIdentifier("continue-on-error", true);
    continueOnError.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(continueOnError);

    ratePerSecond = new IntegerArgument('r', "ratePerSecond", false, 1,
         INFO_PLACEHOLDER_NUM.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_RATE_PER_SECOND.get(), 1,
         Integer.MAX_VALUE);
    ratePerSecond.addLongIdentifier("rate-per-second", true);
    ratePerSecond.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(ratePerSecond);

    useAdministrativeSession = new BooleanArgument(null,
         "useAdministrativeSession", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_USE_ADMIN_SESSION.get());
    useAdministrativeSession.addLongIdentifier("use-administrative-session",
         true);
    useAdministrativeSession.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(useAdministrativeSession);

    dryRun = new BooleanArgument('n', "dryRun", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_DRY_RUN.get());
    dryRun.addLongIdentifier("dry-run", true);
    dryRun.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    parser.addArgument(dryRun);

    wrapColumn = new IntegerArgument(null, "wrapColumn", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_WRAP_COLUMN.get(), 0,
         Integer.MAX_VALUE);
    wrapColumn.addLongIdentifier("wrap-column", true);
    wrapColumn.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(wrapColumn);

    dontWrap = new BooleanArgument('T', "dontWrap", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_DONT_WRAP.get());
    dontWrap.addLongIdentifier("doNotWrap", true);
    dontWrap.addLongIdentifier("dont-wrap", true);
    dontWrap.addLongIdentifier("do-not-wrap", true);
    dontWrap.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(dontWrap);

    suppressBase64EncodedValueComments = new BooleanArgument(null,
         "suppressBase64EncodedValueComments", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SUPPRESS_BASE64_COMMENTS.get());
    suppressBase64EncodedValueComments.addLongIdentifier(
         "suppress-base64-encoded-value-comments", true);
    suppressBase64EncodedValueComments.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(suppressBase64EncodedValueComments);

    countEntries = new BooleanArgument(null, "countEntries", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_COUNT_ENTRIES.get());
    countEntries.addLongIdentifier("count-entries", true);
    countEntries.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_OPS.get());
    countEntries.setHidden(true);
    parser.addArgument(countEntries);

    outputFile = new FileArgument(null, "outputFile", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_OUTPUT_FILE.get(), false, true, true,
         false);
    outputFile.addLongIdentifier("output-file", true);
    outputFile.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(outputFile);

    compressOutput = new BooleanArgument(null, "compressOutput", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_COMPRESS_OUTPUT.get());
    compressOutput.addLongIdentifier("compress-output", true);
    compressOutput.addLongIdentifier("compress", true);
    compressOutput.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(compressOutput);

    encryptOutput = new BooleanArgument(null, "encryptOutput", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ENCRYPT_OUTPUT.get());
    encryptOutput.addLongIdentifier("encrypt-output", true);
    encryptOutput.addLongIdentifier("encrypt", true);
    encryptOutput.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(encryptOutput);

    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ENCRYPTION_PW_FILE.get(), true, true,
         true, false);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    encryptionPassphraseFile.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(encryptionPassphraseFile);

    separateOutputFilePerSearch = new BooleanArgument(null,
         "separateOutputFilePerSearch", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SEPARATE_OUTPUT_FILES.get());
    separateOutputFilePerSearch.addLongIdentifier(
         "separate-output-file-per-search", true);
    separateOutputFilePerSearch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(separateOutputFilePerSearch);

    teeResultsToStandardOut = new BooleanArgument(null,
         "teeResultsToStandardOut", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_TEE.get("outputFile"));
    teeResultsToStandardOut.addLongIdentifier(
         "tee-results-to-standard-out", true);
    teeResultsToStandardOut.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(teeResultsToStandardOut);

    final Set<String> outputFormatAllowedValues = StaticUtils.setOf("ldif",
         "json", "csv", "multi-valued-csv", "tab-delimited",
         "multi-valued-tab-delimited", "dns-only", "values-only");
    outputFormat = new StringArgument(null, "outputFormat", false, 1,
         "{ldif|json|csv|multi-valued-csv|tab-delimited|" +
              "multi-valued-tab-delimited|dns-only|values-only}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_OUTPUT_FORMAT.get(
              requestedAttribute.getIdentifierString(),
              ldapURLFile.getIdentifierString()),
         outputFormatAllowedValues, "ldif");
    outputFormat.addLongIdentifier("output-format", true);
    outputFormat.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(outputFormat);

    requireMatch = new BooleanArgument(null, "requireMatch", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_REQUIRE_MATCH.get(
              getToolName(),
              String.valueOf(ResultCode.NO_RESULTS_RETURNED)));
    requireMatch.addLongIdentifier("require-match", true);
    requireMatch.addLongIdentifier("requireMatchingEntry", true);
    requireMatch.addLongIdentifier("require-matching-entry", true);
    requireMatch.addLongIdentifier("requireMatchingEntries", true);
    requireMatch.addLongIdentifier("require-matching-entries", true);
    requireMatch.addLongIdentifier("requireEntry", true);
    requireMatch.addLongIdentifier("require-entry", true);
    requireMatch.addLongIdentifier("requireEntries", true);
    requireMatch.addLongIdentifier("require-entries", true);
    requireMatch.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(requireMatch);

    terse = new BooleanArgument(null, "terse", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_TERSE.get());
    terse.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(terse);

    verbose = new BooleanArgument('v', "verbose", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_VERBOSE.get());
    verbose.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(verbose);

    bindControl = new ControlArgument(null, "bindControl", false, 0, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_BIND_CONTROL.get());
    bindControl.addLongIdentifier("bind-control", true);
    bindControl.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(bindControl);

    searchControl = new ControlArgument('J', "control", false, 0, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SEARCH_CONTROL.get());
    searchControl.addLongIdentifier("searchControl", true);
    searchControl.addLongIdentifier("search-control", true);
    searchControl.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(searchControl);

    authorizationIdentity = new BooleanArgument('E', "authorizationIdentity",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_AUTHZ_IDENTITY.get());
    authorizationIdentity.addLongIdentifier("reportAuthzID", true);
    authorizationIdentity.addLongIdentifier("authorization-identity", true);
    authorizationIdentity.addLongIdentifier("report-authzid", true);
    authorizationIdentity.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(authorizationIdentity);

    assertionFilter = new FilterArgument(null, "assertionFilter", false, 1,
         INFO_PLACEHOLDER_FILTER.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ASSERTION_FILTER.get());
    assertionFilter.addLongIdentifier("assertion-filter", true);
    assertionFilter.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(assertionFilter);

    accountUsable = new BooleanArgument(null, "accountUsable", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ACCOUNT_USABLE.get());
    accountUsable.addLongIdentifier("account-usable", true);
    accountUsable.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(accountUsable);

    excludeBranch = new DNArgument(null, "excludeBranch", false, 0, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_EXCLUDE_BRANCH.get());
    excludeBranch.addLongIdentifier("exclude-branch", true);
    excludeBranch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(excludeBranch);

    getAuthorizationEntryAttribute = new StringArgument(null,
         "getAuthorizationEntryAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_AUTHZ_ENTRY_ATTR.get());
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authorization-entry-attribute", true);
    getAuthorizationEntryAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getAuthorizationEntryAttribute);

    getBackendSetID = new BooleanArgument(null, "getBackendSetID",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_BACKEND_SET_ID.get());
    getBackendSetID.addLongIdentifier("get-backend-set-id", true);
    getBackendSetID.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getBackendSetID);

    getEffectiveRightsAuthzID = new StringArgument('g',
         "getEffectiveRightsAuthzID", false, 1,
         INFO_PLACEHOLDER_AUTHZID.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_EFFECTIVE_RIGHTS_AUTHZID.get(
              "getEffectiveRightsAttribute"));
    getEffectiveRightsAuthzID.addLongIdentifier(
         "get-effective-rights-authzid", true);
    getEffectiveRightsAuthzID.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getEffectiveRightsAuthzID);

    getEffectiveRightsAttribute = new StringArgument('e',
         "getEffectiveRightsAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_EFFECTIVE_RIGHTS_ATTR.get());
    getEffectiveRightsAttribute.addLongIdentifier(
         "get-effective-rights-attribute", true);
    getEffectiveRightsAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getEffectiveRightsAttribute);

    getRecentLoginHistory = new BooleanArgument(null, "getRecentLoginHistory",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_RECENT_LOGIN_HISTORY.get());
    getRecentLoginHistory.addLongIdentifier("get-recent-login-history", true);
    getRecentLoginHistory.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getRecentLoginHistory);

    getServerID = new BooleanArgument(null, "getServerID",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_SERVER_ID.get());
    getServerID.addLongIdentifier("get-server-id", true);
    getServerID.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getServerID);

    getUserResourceLimits = new BooleanArgument(null, "getUserResourceLimits",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_USER_RESOURCE_LIMITS.get());
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits", true);
    getUserResourceLimits.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getUserResourceLimits);

    includeReplicationConflictEntries = new BooleanArgument(null,
         "includeReplicationConflictEntries", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_REPL_CONFLICTS.get());
    includeReplicationConflictEntries.addLongIdentifier(
         "include-replication-conflict-entries", true);
    includeReplicationConflictEntries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(includeReplicationConflictEntries);

    final Set<String> softDeleteAllowedValues = StaticUtils.setOf(
         "with-non-deleted-entries", "without-non-deleted-entries",
         "deleted-entries-in-undeleted-form");
    includeSoftDeletedEntries = new StringArgument(null,
         "includeSoftDeletedEntries", false, 1,
         "{with-non-deleted-entries|without-non-deleted-entries|" +
              "deleted-entries-in-undeleted-form}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_SOFT_DELETED.get(),
         softDeleteAllowedValues);
    includeSoftDeletedEntries.addLongIdentifier(
         "include-soft-deleted-entries", true);
    includeSoftDeletedEntries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(includeSoftDeletedEntries);

    draftLDUPSubentries = new BooleanArgument(null, "draftLDUPSubentries", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_DRAFT_LDUP_SUBENTRIES.get());
    draftLDUPSubentries.addLongIdentifier("draftIETFLDUPSubentries", true);
    draftLDUPSubentries.addLongIdentifier("includeSubentries", true);
    draftLDUPSubentries.addLongIdentifier("includeLDAPSubentries", true);
    draftLDUPSubentries.addLongIdentifier("draft-ldup-subentries", true);
    draftLDUPSubentries.addLongIdentifier("draft-ietf-ldup-subentries", true);
    draftLDUPSubentries.addLongIdentifier("include-subentries", true);
    draftLDUPSubentries.addLongIdentifier("include-ldap-subentries", true);
    draftLDUPSubentries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(draftLDUPSubentries);

    rfc3672Subentries = new BooleanValueArgument(null, "rfc3672Subentries",
         false,
         INFO_LDAPSEARCH_ARG_PLACEHOLDER_INCLUDE_RFC_3672_SUBENTRIES.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_RFC_3672_SUBENTRIES.get());
    rfc3672Subentries.addLongIdentifier("rfc-3672-subentries", true);
    rfc3672Subentries.addLongIdentifier("rfc3672-subentries", true);
    rfc3672Subentries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(rfc3672Subentries);

    joinRule = new StringArgument(null, "joinRule", false, 1,
         "{dn:sourceAttr|reverse-dn:targetAttr|equals:sourceAttr:targetAttr|" +
              "contains:sourceAttr:targetAttr }",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_RULE.get());
    joinRule.addLongIdentifier("join-rule", true);
    joinRule.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinRule);

    joinBaseDN = new StringArgument(null, "joinBaseDN", false, 1,
         "{search-base|source-entry-dn|{dn}}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_BASE_DN.get());
    joinBaseDN.addLongIdentifier("join-base-dn", true);
    joinBaseDN.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinBaseDN);

    joinScope = new ScopeArgument(null, "joinScope", false, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_SCOPE.get());
    joinScope.addLongIdentifier("join-scope", true);
    joinScope.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinScope);

    joinSizeLimit = new IntegerArgument(null, "joinSizeLimit", false, 1,
         INFO_PLACEHOLDER_NUM.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_SIZE_LIMIT.get(), 0,
         Integer.MAX_VALUE);
    joinSizeLimit.addLongIdentifier("join-size-limit", true);
    joinSizeLimit.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinSizeLimit);

    joinFilter = new FilterArgument(null, "joinFilter", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_FILTER.get());
    joinFilter.addLongIdentifier("join-filter", true);
    joinFilter.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinFilter);

    joinRequestedAttribute = new StringArgument(null, "joinRequestedAttribute",
         false, 0, INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_ATTR.get());
    joinRequestedAttribute.addLongIdentifier("join-requested-attribute", true);
    joinRequestedAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinRequestedAttribute);

    joinRequireMatch = new BooleanArgument(null, "joinRequireMatch", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_JOIN_REQUIRE_MATCH.get());
    joinRequireMatch.addLongIdentifier("join-require-match", true);
    joinRequireMatch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(joinRequireMatch);

    manageDsaIT = new BooleanArgument(null, "manageDsaIT", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_MANAGE_DSA_IT.get());
    manageDsaIT.addLongIdentifier("manage-dsa-it", true);
    manageDsaIT.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(manageDsaIT);

    matchedValuesFilter = new FilterArgument(null, "matchedValuesFilter",
         false, 0, INFO_PLACEHOLDER_FILTER.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_MATCHED_VALUES_FILTER.get());
    matchedValuesFilter.addLongIdentifier("matched-values-filter", true);
    matchedValuesFilter.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(matchedValuesFilter);

    matchingEntryCountControl = new StringArgument(null,
         "matchingEntryCountControl", false, 1,
         "{examineCount=NNN[:alwaysExamine][:allowUnindexed]" +
              "[:skipResolvingExplodedIndexes]" +
              "[:fastShortCircuitThreshold=NNN]" +
              "[:slowShortCircuitThreshold=NNN][:debug]}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_MATCHING_ENTRY_COUNT_CONTROL.get());
    matchingEntryCountControl.addLongIdentifier("matchingEntryCount", true);
    matchingEntryCountControl.addLongIdentifier(
         "matching-entry-count-control", true);
    matchingEntryCountControl.addLongIdentifier("matching-entry-count", true);
    matchingEntryCountControl.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(matchingEntryCountControl);

    operationPurpose = new StringArgument(null, "operationPurpose", false, 1,
         INFO_PLACEHOLDER_PURPOSE.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_OPERATION_PURPOSE.get());
    operationPurpose.addLongIdentifier("operation-purpose", true);
    operationPurpose.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(operationPurpose);

    overrideSearchLimit = new StringArgument(null, "overrideSearchLimit",
         false, 0, INFO_LDAPSEARCH_NAME_VALUE_PLACEHOLDER.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_OVERRIDE_SEARCH_LIMIT.get());
    overrideSearchLimit.addLongIdentifier("overrideSearchLimits", true);
    overrideSearchLimit.addLongIdentifier("override-search-limit", true);
    overrideSearchLimit.addLongIdentifier("override-search-limits", true);
    overrideSearchLimit.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(overrideSearchLimit);

    persistentSearch = new StringArgument('C', "persistentSearch", false, 1,
         "ps[:changetype[:changesonly[:entrychgcontrols]]]",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_PERSISTENT_SEARCH.get());
    persistentSearch.addLongIdentifier("persistent-search", true);
    persistentSearch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(persistentSearch);

    permitUnindexedSearch = new BooleanArgument(null, "permitUnindexedSearch",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_PERMIT_UNINDEXED_SEARCH.get());
    permitUnindexedSearch.addLongIdentifier("permitUnindexedSearches", true);
    permitUnindexedSearch.addLongIdentifier("permitUnindexed", true);
    permitUnindexedSearch.addLongIdentifier("permitIfUnindexed", true);
    permitUnindexedSearch.addLongIdentifier("permit-unindexed-search", true);
    permitUnindexedSearch.addLongIdentifier("permit-unindexed-searches", true);
    permitUnindexedSearch.addLongIdentifier("permit-unindexed", true);
    permitUnindexedSearch.addLongIdentifier("permit-if-unindexed", true);
    permitUnindexedSearch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(permitUnindexedSearch);

    proxyAs = new StringArgument('Y', "proxyAs", false, 1,
         INFO_PLACEHOLDER_AUTHZID.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_PROXY_AS.get());
    proxyAs.addLongIdentifier("proxy-as", true);
    proxyAs.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(proxyAs);

    proxyV1As = new DNArgument(null, "proxyV1As", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_PROXY_V1_AS.get());
    proxyV1As.addLongIdentifier("proxy-v1-as", true);
    proxyV1As.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(proxyV1As);

    rejectUnindexedSearch = new BooleanArgument(null, "rejectUnindexedSearch",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_REJECT_UNINDEXED_SEARCH.get());
    rejectUnindexedSearch.addLongIdentifier("rejectUnindexedSearches", true);
    rejectUnindexedSearch.addLongIdentifier("rejectUnindexed", true);
    rejectUnindexedSearch.addLongIdentifier("rejectIfUnindexed", true);
    rejectUnindexedSearch.addLongIdentifier("reject-unindexed-search", true);
    rejectUnindexedSearch.addLongIdentifier("reject-unindexed-searches", true);
    rejectUnindexedSearch.addLongIdentifier("reject-unindexed", true);
    rejectUnindexedSearch.addLongIdentifier("reject-if-unindexed", true);
    rejectUnindexedSearch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(rejectUnindexedSearch);

    routeToBackendSet = new StringArgument(null, "routeToBackendSet",
         false, 0,
         INFO_LDAPSEARCH_ARG_PLACEHOLDER_ROUTE_TO_BACKEND_SET.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ROUTE_TO_BACKEND_SET.get());
    routeToBackendSet.addLongIdentifier("route-to-backend-set", true);
    routeToBackendSet.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(routeToBackendSet);

    routeToServer = new StringArgument(null, "routeToServer", false, 1,
         INFO_LDAPSEARCH_ARG_PLACEHOLDER_ROUTE_TO_SERVER.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_ROUTE_TO_SERVER.get());
    routeToServer.addLongIdentifier("route-to-server", true);
    routeToServer.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(routeToServer);

    final Set<String> suppressOperationalAttributeUpdatesAllowedValues =
         StaticUtils.setOf("last-access-time", "last-login-time",
              "last-login-ip", "lastmod");
    suppressOperationalAttributeUpdates = new StringArgument(null,
         "suppressOperationalAttributeUpdates", false, -1,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SUPPRESS_OP_ATTR_UPDATES.get(),
         suppressOperationalAttributeUpdatesAllowedValues);
    suppressOperationalAttributeUpdates.addLongIdentifier(
         "suppress-operational-attribute-updates", true);
    suppressOperationalAttributeUpdates.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(suppressOperationalAttributeUpdates);

    usePasswordPolicyControl = new BooleanArgument(null,
         "usePasswordPolicyControl", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_PASSWORD_POLICY.get());
    usePasswordPolicyControl.addLongIdentifier("use-password-policy-control",
         true);
    usePasswordPolicyControl.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(usePasswordPolicyControl);

    realAttributesOnly = new BooleanArgument(null, "realAttributesOnly", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_REAL_ATTRS_ONLY.get());
    realAttributesOnly.addLongIdentifier("real-attributes-only", true);
    realAttributesOnly.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(realAttributesOnly);

    sortOrder = new StringArgument('S', "sortOrder", false, 1, null,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SORT_ORDER.get());
    sortOrder.addLongIdentifier("sort-order", true);
    sortOrder.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(sortOrder);

    simplePageSize = new IntegerArgument(null, "simplePageSize", false, 1,
         null, INFO_LDAPSEARCH_ARG_DESCRIPTION_PAGE_SIZE.get(), 1,
         Integer.MAX_VALUE);
    simplePageSize.addLongIdentifier("simple-page-size", true);
    simplePageSize.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(simplePageSize);

    virtualAttributesOnly = new BooleanArgument(null,
         "virtualAttributesOnly", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_VIRTUAL_ATTRS_ONLY.get());
    virtualAttributesOnly.addLongIdentifier("virtual-attributes-only", true);
    virtualAttributesOnly.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(virtualAttributesOnly);

    virtualListView = new StringArgument('G', "virtualListView", false, 1,
         "{before:after:index:count | before:after:value}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_VLV.get("sortOrder"));
    virtualListView.addLongIdentifier("vlv", true);
    virtualListView.addLongIdentifier("virtual-list-view", true);
    virtualListView.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(virtualListView);

    excludeAttribute = new StringArgument(null, "excludeAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_EXCLUDE_ATTRIBUTE.get());
    excludeAttribute.addLongIdentifier("exclude-attribute", true);
    excludeAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(excludeAttribute);

    redactAttribute = new StringArgument(null, "redactAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_REDACT_ATTRIBUTE.get());
    redactAttribute.addLongIdentifier("redact-attribute", true);
    redactAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(redactAttribute);

    hideRedactedValueCount = new BooleanArgument(null, "hideRedactedValueCount",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_HIDE_REDACTED_VALUE_COUNT.get());
    hideRedactedValueCount.addLongIdentifier("hide-redacted-value-count", true);
    hideRedactedValueCount.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(hideRedactedValueCount);

    scrambleAttribute = new StringArgument(null, "scrambleAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SCRAMBLE_ATTRIBUTE.get());
    scrambleAttribute.addLongIdentifier("scramble-attribute", true);
    scrambleAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(scrambleAttribute);

    scrambleJSONField = new StringArgument(null, "scrambleJSONField", false, 0,
         INFO_PLACEHOLDER_FIELD_NAME.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SCRAMBLE_JSON_FIELD.get());
    scrambleJSONField.addLongIdentifier("scramble-json-field", true);
    scrambleJSONField.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(scrambleJSONField);

    scrambleRandomSeed = new IntegerArgument(null, "scrambleRandomSeed", false,
         1, null, INFO_LDAPSEARCH_ARG_DESCRIPTION_SCRAMBLE_RANDOM_SEED.get());
    scrambleRandomSeed.addLongIdentifier("scramble-random-seed", true);
    scrambleRandomSeed.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(scrambleRandomSeed);

    renameAttributeFrom = new StringArgument(null, "renameAttributeFrom", false,
         0, INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_RENAME_ATTRIBUTE_FROM.get());
    renameAttributeFrom.addLongIdentifier("rename-attribute-from", true);
    renameAttributeFrom.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(renameAttributeFrom);

    renameAttributeTo = new StringArgument(null, "renameAttributeTo", false,
         0, INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_RENAME_ATTRIBUTE_TO.get());
    renameAttributeTo.addLongIdentifier("rename-attribute-to", true);
    renameAttributeTo.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(renameAttributeTo);

    moveSubtreeFrom = new DNArgument(null, "moveSubtreeFrom", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_MOVE_SUBTREE_FROM.get());
    moveSubtreeFrom.addLongIdentifier("move-subtree-from", true);
    moveSubtreeFrom.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(moveSubtreeFrom);

    moveSubtreeTo = new DNArgument(null, "moveSubtreeTo", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_MOVE_SUBTREE_TO.get());
    moveSubtreeTo.addLongIdentifier("move-subtree-to", true);
    moveSubtreeTo.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_TRANSFORMATIONS.get());
    parser.addArgument(moveSubtreeTo);


    // The "--scriptFriendly" argument is provided for compatibility with legacy
    // ldapsearch tools, but is not actually used by this tool.
    final BooleanArgument scriptFriendly = new BooleanArgument(null,
         "scriptFriendly", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SCRIPT_FRIENDLY.get());
    scriptFriendly.addLongIdentifier("script-friendly", true);
    scriptFriendly.setHidden(true);
    parser.addArgument(scriptFriendly);


    // The "-V" / "--ldapVersion" argument is provided for compatibility with
    // legacy ldapsearch tools, but is not actually used by this tool.
    final IntegerArgument ldapVersion = new IntegerArgument('V', "ldapVersion",
         false, 1, null, INFO_LDAPSEARCH_ARG_DESCRIPTION_LDAP_VERSION.get());
    ldapVersion.addLongIdentifier("ldap-version", true);
    ldapVersion.setHidden(true);
    parser.addArgument(ldapVersion);


    // The baseDN and ldapURLFile arguments can't be used together.
    parser.addExclusiveArgumentSet(baseDN, ldapURLFile);

    // The scope and ldapURLFile arguments can't be used together.
    parser.addExclusiveArgumentSet(scope, ldapURLFile);

    // The requestedAttribute and ldapURLFile arguments can't be used together.
    parser.addExclusiveArgumentSet(requestedAttribute, ldapURLFile);

    // The filter and ldapURLFile arguments can't be used together.
    parser.addExclusiveArgumentSet(filter, ldapURLFile);

    // The filterFile and ldapURLFile arguments can't be used together.
    parser.addExclusiveArgumentSet(filterFile, ldapURLFile);

    // The followReferrals and manageDsaIT arguments can't be used together.
    parser.addExclusiveArgumentSet(followReferrals, manageDsaIT);

    // The persistent search argument can't be used with either the filterFile
    // or ldapURLFile arguments.
    parser.addExclusiveArgumentSet(persistentSearch, filterFile);
    parser.addExclusiveArgumentSet(persistentSearch, ldapURLFile);

    // The draft-ietf-ldup-subentry and RFC 3672 subentries controls cannot be
    // used together.
    parser.addExclusiveArgumentSet(draftLDUPSubentries, rfc3672Subentries);

    // The realAttributesOnly and virtualAttributesOnly arguments can't be used
    // together.
    parser.addExclusiveArgumentSet(realAttributesOnly, virtualAttributesOnly);

    // The simplePageSize and virtualListView arguments can't be used together.
    parser.addExclusiveArgumentSet(simplePageSize, virtualListView);

    // The terse and verbose arguments can't be used together.
    parser.addExclusiveArgumentSet(terse, verbose);

    // The getEffectiveRightsAttribute argument requires the
    // getEffectiveRightsAuthzID argument.
    parser.addDependentArgumentSet(getEffectiveRightsAttribute,
         getEffectiveRightsAuthzID);

    // The virtualListView argument requires the sortOrder argument.
    parser.addDependentArgumentSet(virtualListView, sortOrder);

    // The rejectUnindexedSearch and permitUnindexedSearch arguments can't be
    // used together.
    parser.addExclusiveArgumentSet(rejectUnindexedSearch,
         permitUnindexedSearch);

    // The separateOutputFilePerSearch argument requires the outputFile
    // argument.  It also requires either the filter, filterFile or ldapURLFile
    // argument.
    parser.addDependentArgumentSet(separateOutputFilePerSearch, outputFile);
    parser.addDependentArgumentSet(separateOutputFilePerSearch, filter,
         filterFile, ldapURLFile);

    // The teeResultsToStandardOut argument requires the outputFile argument.
    parser.addDependentArgumentSet(teeResultsToStandardOut, outputFile);

    // The wrapColumn and dontWrap arguments must not be used together.
    parser.addExclusiveArgumentSet(wrapColumn, dontWrap);

    // All arguments that specifically pertain to join processing can only be
    // used if the joinRule argument is provided.
    parser.addDependentArgumentSet(joinBaseDN, joinRule);
    parser.addDependentArgumentSet(joinScope, joinRule);
    parser.addDependentArgumentSet(joinSizeLimit, joinRule);
    parser.addDependentArgumentSet(joinFilter, joinRule);
    parser.addDependentArgumentSet(joinRequestedAttribute, joinRule);
    parser.addDependentArgumentSet(joinRequireMatch, joinRule);

    // The countEntries argument must not be used in conjunction with the
    // filter, filterFile, LDAPURLFile, or persistentSearch arguments.
    parser.addExclusiveArgumentSet(countEntries, filter);
    parser.addExclusiveArgumentSet(countEntries, filterFile);
    parser.addExclusiveArgumentSet(countEntries, ldapURLFile);
    parser.addExclusiveArgumentSet(countEntries, persistentSearch);


    // The hideRedactedValueCount argument requires the redactAttribute
    // argument.
    parser.addDependentArgumentSet(hideRedactedValueCount, redactAttribute);

    // The scrambleJSONField and scrambleRandomSeed arguments require the
    // scrambleAttribute argument.
    parser.addDependentArgumentSet(scrambleJSONField, scrambleAttribute);
    parser.addDependentArgumentSet(scrambleRandomSeed, scrambleAttribute);

    // The renameAttributeFrom and renameAttributeTo arguments must be provided
    // together.
    parser.addDependentArgumentSet(renameAttributeFrom, renameAttributeTo);
    parser.addDependentArgumentSet(renameAttributeTo, renameAttributeFrom);

    // The moveSubtreeFrom and moveSubtreeTo arguments must be provided
    // together.
    parser.addDependentArgumentSet(moveSubtreeFrom, moveSubtreeTo);
    parser.addDependentArgumentSet(moveSubtreeTo, moveSubtreeFrom);


    // The compressOutput argument can only be used if an output file is
    // specified and results aren't going to be teed.
    parser.addDependentArgumentSet(compressOutput, outputFile);
    parser.addExclusiveArgumentSet(compressOutput, teeResultsToStandardOut);


    // The encryptOutput argument can only be used if an output file is
    // specified and results aren't going to be teed.
    parser.addDependentArgumentSet(encryptOutput, outputFile);
    parser.addExclusiveArgumentSet(encryptOutput, teeResultsToStandardOut);


    // The encryptionPassphraseFile argument can only be used if the
    // encryptOutput argument is also provided.
    parser.addDependentArgumentSet(encryptionPassphraseFile, encryptOutput);
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
      bindControls.add(new AuthorizationIdentityRequestControl(false));
    }

    if (getAuthorizationEntryAttribute.isPresent())
    {
      bindControls.add(new GetAuthorizationEntryRequestControl(true, true,
           getAuthorizationEntryAttribute.getValues()));
    }

    if (getRecentLoginHistory.isPresent())
    {
      bindControls.add(new GetRecentLoginHistoryRequestControl());
    }

    if (getUserResourceLimits.isPresent())
    {
      bindControls.add(new GetUserResourceLimitsRequestControl());
    }

    if (usePasswordPolicyControl.isPresent())
    {
      bindControls.add(new PasswordPolicyRequestControl());
    }

    if (suppressOperationalAttributeUpdates.isPresent())
    {
      final EnumSet<SuppressType> suppressTypes =
           EnumSet.noneOf(SuppressType.class);
      for (final String s : suppressOperationalAttributeUpdates.getValues())
      {
        if (s.equalsIgnoreCase("last-access-time"))
        {
          suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
        }
        else if (s.equalsIgnoreCase("last-login-time"))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
        }
        else if (s.equalsIgnoreCase("last-login-ip"))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_IP);
        }
      }

      bindControls.add(new SuppressOperationalAttributeUpdateRequestControl(
           suppressTypes));
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
    // accept information about multiple servers in the event that multiple
    // searches are to be performed and a server goes down in the middle of
    // those searches.  In this case, we can resume processing on a
    // newly-created connection, possibly to a different server.
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // If wrapColumn was provided, then use its value.  Otherwise, if dontWrap
    // was provided, then use that.
    if (wrapColumn.isPresent())
    {
      final int wc = wrapColumn.getValue();
      if (wc <= 0)
      {
        WRAP_COLUMN = Integer.MAX_VALUE;
      }
      else
      {
        WRAP_COLUMN = wc;
      }
    }
    else if (dontWrap.isPresent())
    {
      WRAP_COLUMN = Integer.MAX_VALUE;
    }


    // If the ldapURLFile argument was provided, then there must not be any
    // trailing arguments.
    final List<String> trailingArgs = parser.getTrailingArguments();
    if (ldapURLFile.isPresent())
    {
      if (! trailingArgs.isEmpty())
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_TRAILING_ARGS_WITH_URL_FILE.get(
                  ldapURLFile.getIdentifierString()));
      }
    }


    // If the filter or filterFile argument was provided, then there may
    // optionally be trailing arguments, but the first trailing argument must
    // not be a filter.
    if (filter.isPresent() || filterFile.isPresent())
    {
      if (! trailingArgs.isEmpty())
      {
        try
        {
          Filter.create(trailingArgs.get(0));
          throw new ArgumentException(
               ERR_LDAPSEARCH_TRAILING_FILTER_WITH_FILTER_FILE.get(
                    filterFile.getIdentifierString()));
        }
        catch (final LDAPException le)
        {
          // This is the normal condition.  Not even worth debugging the
          // exception.
        }
      }
    }


    // If none of the ldapURLFile, filter, or filterFile arguments was provided,
    // then there must be at least one trailing argument, and the first trailing
    // argument must be a valid search filter.
    if (! (ldapURLFile.isPresent() || filter.isPresent() ||
           filterFile.isPresent()))
    {
      if (trailingArgs.isEmpty())
      {
        throw new ArgumentException(ERR_LDAPSEARCH_NO_TRAILING_ARGS.get(
             filterFile.getIdentifierString(),
             ldapURLFile.getIdentifierString()));
      }

      try
      {
        Filter.create(trailingArgs.get(0));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAPSEARCH_FIRST_TRAILING_ARG_NOT_FILTER.get(
                  trailingArgs.get(0)),
             e);
      }
    }


    // There should never be a case in which a trailing argument starts with a
    // dash, and it's probably an attempt to use a named argument but that was
    // inadvertently put after the filter.  Warn about the problem, but don't
    // fail.
    for (final String s : trailingArgs)
    {
      if (s.startsWith("-"))
      {
        commentToErr(WARN_LDAPSEARCH_TRAILING_ARG_STARTS_WITH_DASH.get(s));
        break;
      }
    }


    // If any matched values filters are specified, then validate them and
    // pre-create the matched values request control.
    if (matchedValuesFilter.isPresent())
    {
      final List<Filter> filterList = matchedValuesFilter.getValues();
      final MatchedValuesFilter[] matchedValuesFilters =
           new MatchedValuesFilter[filterList.size()];
      for (int i=0; i < matchedValuesFilters.length; i++)
      {
        try
        {
          matchedValuesFilters[i] =
               MatchedValuesFilter.create(filterList.get(i));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new ArgumentException(
               ERR_LDAPSEARCH_INVALID_MATCHED_VALUES_FILTER.get(
                    filterList.get(i).toString()),
               e);
        }
      }

      matchedValuesRequestControl =
           new MatchedValuesRequestControl(true, matchedValuesFilters);
    }


    // If we should use the matching entry count request control, then validate
    // the argument value and pre-create the control.
    if (matchingEntryCountControl.isPresent())
    {
      boolean allowUnindexed               = false;
      boolean alwaysExamine                = false;
      boolean debug                        = false;
      boolean skipResolvingExplodedIndexes = false;
      Integer examineCount                 = null;
      Long    fastShortCircuitThreshold    = null;
      Long    slowShortCircuitThreshold    = null;

      try
      {
        for (final String element :
             matchingEntryCountControl.getValue().toLowerCase().split(":"))
        {
          if (element.startsWith("examinecount="))
          {
            examineCount = Integer.parseInt(element.substring(13));
          }
          else if (element.equals("allowunindexed"))
          {
            allowUnindexed = true;
          }
          else if (element.equals("alwaysexamine"))
          {
            alwaysExamine = true;
          }
          else if (element.equals("skipresolvingexplodedindexes"))
          {
            skipResolvingExplodedIndexes = true;
          }
          else if (element.startsWith("fastshortcircuitthreshold="))
          {
            fastShortCircuitThreshold = Long.parseLong(element.substring(26));
          }
          else if (element.startsWith("slowshortcircuitthreshold="))
          {
            slowShortCircuitThreshold = Long.parseLong(element.substring(26));
          }
          else if (element.equals("debug"))
          {
            debug = true;
          }
          else
          {
            throw new ArgumentException(
                 ERR_LDAPSEARCH_MATCHING_ENTRY_COUNT_INVALID_VALUE.get(
                      matchingEntryCountControl.getIdentifierString()));
          }
        }
      }
      catch (final ArgumentException ae)
      {
        Debug.debugException(ae);
        throw ae;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAPSEARCH_MATCHING_ENTRY_COUNT_INVALID_VALUE.get(
                  matchingEntryCountControl.getIdentifierString()),
             e);
      }

      if (examineCount == null)
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_MATCHING_ENTRY_COUNT_INVALID_VALUE.get(
                  matchingEntryCountControl.getIdentifierString()));
      }

      matchingEntryCountRequestControl = new MatchingEntryCountRequestControl(
           true, examineCount, alwaysExamine, allowUnindexed,
           skipResolvingExplodedIndexes, fastShortCircuitThreshold,
           slowShortCircuitThreshold, debug);
    }


    // If we should include the override search limits request control, then
    // validate the provided values.
    if (overrideSearchLimit.isPresent())
    {
      final LinkedHashMap<String,String> properties =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
      for (final String value : overrideSearchLimit.getValues())
      {
        final int equalPos = value.indexOf('=');
        if (equalPos < 0)
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_OVERRIDE_LIMIT_NO_EQUAL.get(
                    overrideSearchLimit.getIdentifierString()));
        }
        else if (equalPos == 0)
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_OVERRIDE_LIMIT_EMPTY_PROPERTY_NAME.get(
                    overrideSearchLimit.getIdentifierString()));
        }

        final String propertyName = value.substring(0, equalPos);
        if (properties.containsKey(propertyName))
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_OVERRIDE_LIMIT_DUPLICATE_PROPERTY_NAME.get(
                    overrideSearchLimit.getIdentifierString(), propertyName));
        }

        if (equalPos == (value.length() - 1))
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_OVERRIDE_LIMIT_EMPTY_PROPERTY_VALUE.get(
                    overrideSearchLimit.getIdentifierString(), propertyName));
        }

        properties.put(propertyName, value.substring(equalPos+1));
      }

      overrideSearchLimitsRequestControl =
           new OverrideSearchLimitsRequestControl(properties, false);
    }


    // If we should use the persistent search request control, then validate
    // the argument value and pre-create the control.
    if (persistentSearch.isPresent())
    {
      boolean changesOnly = true;
      boolean returnECs   = true;
      EnumSet<PersistentSearchChangeType> changeTypes =
           EnumSet.allOf(PersistentSearchChangeType.class);
      try
      {
        final String[] elements =
             persistentSearch.getValue().toLowerCase().split(":");
        if (elements.length == 0)
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                    persistentSearch.getIdentifierString()));
        }

        final String header = StaticUtils.toLowerCase(elements[0]);
        if (! (header.equals("ps") || header.equals("persist") ||
             header.equals("persistent") || header.equals("psearch") ||
             header.equals("persistentsearch")))
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                    persistentSearch.getIdentifierString()));
        }

        if (elements.length > 1)
        {
          final String ctString = StaticUtils.toLowerCase(elements[1]);
          if (ctString.equals("any"))
          {
            changeTypes = EnumSet.allOf(PersistentSearchChangeType.class);
          }
          else
          {
            changeTypes.clear();
            for (final String t : ctString.split(","))
            {
              if (t.equals("add"))
              {
                changeTypes.add(PersistentSearchChangeType.ADD);
              }
              else if (t.equals("del") || t.equals("delete"))
              {
                changeTypes.add(PersistentSearchChangeType.DELETE);
              }
              else if (t.equals("mod") || t.equals("modify"))
              {
                changeTypes.add(PersistentSearchChangeType.MODIFY);
              }
              else if (t.equals("moddn") || t.equals("modrdn") ||
                   t.equals("modifydn") || t.equals("modifyrdn"))
              {
                changeTypes.add(PersistentSearchChangeType.MODIFY_DN);
              }
              else
              {
                throw new ArgumentException(
                     ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                          persistentSearch.getIdentifierString()));
              }
            }
          }
        }

        if (elements.length > 2)
        {
          if (elements[2].equalsIgnoreCase("true") || elements[2].equals("1"))
          {
            changesOnly = true;
          }
          else if (elements[2].equalsIgnoreCase("false") ||
               elements[2].equals("0"))
          {
            changesOnly = false;
          }
          else
          {
            throw new ArgumentException(
                 ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                      persistentSearch.getIdentifierString()));
          }
        }

        if (elements.length > 3)
        {
          if (elements[3].equalsIgnoreCase("true") || elements[3].equals("1"))
          {
            returnECs = true;
          }
          else if (elements[3].equalsIgnoreCase("false") ||
               elements[3].equals("0"))
          {
            returnECs = false;
          }
          else
          {
            throw new ArgumentException(
                 ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                      persistentSearch.getIdentifierString()));
          }
        }
      }
      catch (final ArgumentException ae)
      {
        Debug.debugException(ae);
        throw ae;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAPSEARCH_PERSISTENT_SEARCH_INVALID_VALUE.get(
                  persistentSearch.getIdentifierString()),
             e);
      }

      persistentSearchRequestControl = new PersistentSearchRequestControl(
           changeTypes, changesOnly, returnECs, true);
    }


    // If we should use the server-side sort request control, then validate the
    // sort order and pre-create the control.
    if (sortOrder.isPresent())
    {
      final ArrayList<SortKey> sortKeyList = new ArrayList<>(5);
      final StringTokenizer tokenizer =
           new StringTokenizer(sortOrder.getValue(), ", ");
      while (tokenizer.hasMoreTokens())
      {
        final String token = tokenizer.nextToken();

        final boolean ascending;
        String attributeName;
        if (token.startsWith("-"))
        {
          ascending = false;
          attributeName = token.substring(1);
        }
        else if (token.startsWith("+"))
        {
          ascending = true;
          attributeName = token.substring(1);
        }
        else
        {
          ascending = true;
          attributeName = token;
        }

        final String matchingRuleID;
        final int colonPos = attributeName.indexOf(':');
        if (colonPos >= 0)
        {
          matchingRuleID = attributeName.substring(colonPos+1);
          attributeName = attributeName.substring(0, colonPos);
        }
        else
        {
          matchingRuleID = null;
        }

        final StringBuilder invalidReason = new StringBuilder();
        if (! PersistUtils.isValidLDAPName(attributeName, false, invalidReason))
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_SORT_ORDER_INVALID_VALUE.get(
                    sortOrder.getIdentifierString()));
        }

        sortKeyList.add(
             new SortKey(attributeName, matchingRuleID, (! ascending)));
      }

      if (sortKeyList.isEmpty())
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_SORT_ORDER_INVALID_VALUE.get(
                  sortOrder.getIdentifierString()));
      }

      final SortKey[] sortKeyArray = new SortKey[sortKeyList.size()];
      sortKeyList.toArray(sortKeyArray);

      sortRequestControl = new ServerSideSortRequestControl(sortKeyArray);
    }


    // If we should use the virtual list view request control, then validate the
    // argument value and pre-create the control.
    if (virtualListView.isPresent())
    {
      try
      {
        final String[] elements = virtualListView.getValue().split(":");
        if (elements.length == 4)
        {
          vlvRequestControl = new VirtualListViewRequestControl(
               Integer.parseInt(elements[2]), Integer.parseInt(elements[0]),
               Integer.parseInt(elements[1]), Integer.parseInt(elements[3]),
               null);
        }
        else if (elements.length == 3)
        {
          vlvRequestControl = new VirtualListViewRequestControl(elements[2],
               Integer.parseInt(elements[0]), Integer.parseInt(elements[1]),
               null);
        }
        else
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_VLV_INVALID_VALUE.get(
                    virtualListView.getIdentifierString()));
        }
      }
      catch (final ArgumentException ae)
      {
        Debug.debugException(ae);
        throw ae;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAPSEARCH_VLV_INVALID_VALUE.get(
                  virtualListView.getIdentifierString()),
             e);
      }
    }


    // If we should use the LDAP join request control, then validate and
    // pre-create that control.
    if (joinRule.isPresent())
    {
      final JoinRule rule;
      try
      {
        final String[] elements = joinRule.getValue().toLowerCase().split(":");
        final String ruleName = StaticUtils.toLowerCase(elements[0]);
        if (ruleName.equals("dn"))
        {
          rule = JoinRule.createDNJoin(elements[1]);
        }
        else if (ruleName.equals("reverse-dn") || ruleName.equals("reversedn"))
        {
          rule = JoinRule.createReverseDNJoin(elements[1]);
        }
        else if (ruleName.equals("equals") || ruleName.equals("equality"))
        {
          rule = JoinRule.createEqualityJoin(elements[1], elements[2], false);
        }
        else if (ruleName.equals("contains") || ruleName.equals("substring"))
        {
          rule = JoinRule.createContainsJoin(elements[1], elements[2], false);
        }
        else
        {
          throw new ArgumentException(
               ERR_LDAPSEARCH_JOIN_RULE_INVALID_VALUE.get(
                    joinRule.getIdentifierString()));
        }
      }
      catch (final ArgumentException ae)
      {
        Debug.debugException(ae);
        throw ae;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(
             ERR_LDAPSEARCH_JOIN_RULE_INVALID_VALUE.get(
                  joinRule.getIdentifierString()),
             e);
      }

      final JoinBaseDN joinBase;
      if (joinBaseDN.isPresent())
      {
        final String s = StaticUtils.toLowerCase(joinBaseDN.getValue());
        if (s.equals("search-base") || s.equals("search-base-dn"))
        {
          joinBase = JoinBaseDN.createUseSearchBaseDN();
        }
        else if (s.equals("source-entry-dn") || s.equals("source-dn"))
        {
          joinBase = JoinBaseDN.createUseSourceEntryDN();
        }
        else
        {
          try
          {
            final DN dn = new DN(joinBaseDN.getValue());
            joinBase = JoinBaseDN.createUseCustomBaseDN(joinBaseDN.getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new ArgumentException(
                 ERR_LDAPSEARCH_JOIN_BASE_DN_INVALID_VALUE.get(
                      joinBaseDN.getIdentifierString()),
                 e);
          }
        }
      }
      else
      {
        joinBase = JoinBaseDN.createUseSearchBaseDN();
      }

      final String[] joinAttrs;
      if (joinRequestedAttribute.isPresent())
      {
        final List<String> valueList = joinRequestedAttribute.getValues();
        joinAttrs = new String[valueList.size()];
        valueList.toArray(joinAttrs);
      }
      else
      {
        joinAttrs = null;
      }

      joinRequestControl = new JoinRequestControl(new JoinRequestValue(rule,
           joinBase, joinScope.getValue(), DereferencePolicy.NEVER,
           joinSizeLimit.getValue(), joinFilter.getValue(), joinAttrs,
           joinRequireMatch.isPresent(), null));
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
               ERR_LDAPSEARCH_ROUTE_TO_BACKEND_SET_INVALID_FORMAT.get(value,
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
             RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(true,
                  rpID, bsIDs));
      }
    }


    // Parse the dereference policy.
    final String derefStr =
         StaticUtils.toLowerCase(dereferencePolicy.getValue());
    if (derefStr.equals("always"))
    {
      derefPolicy = DereferencePolicy.ALWAYS;
    }
    else if (derefStr.equals("search"))
    {
      derefPolicy = DereferencePolicy.SEARCHING;
    }
    else if (derefStr.equals("find"))
    {
      derefPolicy = DereferencePolicy.FINDING;
    }
    else
    {
      derefPolicy = DereferencePolicy.NEVER;
    }


    // See if any entry transformations need to be applied.
    final ArrayList<EntryTransformation> transformations = new ArrayList<>(5);
    if (excludeAttribute.isPresent())
    {
      transformations.add(new ExcludeAttributeTransformation(null,
           excludeAttribute.getValues()));
    }

    if (redactAttribute.isPresent())
    {
      transformations.add(new RedactAttributeTransformation(null, true,
           (! hideRedactedValueCount.isPresent()),
           redactAttribute.getValues()));
    }

    if (scrambleAttribute.isPresent())
    {
      final Long randomSeed;
      if (scrambleRandomSeed.isPresent())
      {
        randomSeed = scrambleRandomSeed.getValue().longValue();
      }
      else
      {
        randomSeed = null;
      }

      transformations.add(new ScrambleAttributeTransformation(null, randomSeed,
           true, scrambleAttribute.getValues(), scrambleJSONField.getValues()));
    }

    if (renameAttributeFrom.isPresent())
    {
      if (renameAttributeFrom.getNumOccurrences() !=
          renameAttributeTo.getNumOccurrences())
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_RENAME_ATTRIBUTE_MISMATCH.get());
      }

      final Iterator<String> sourceIterator =
           renameAttributeFrom.getValues().iterator();
      final Iterator<String> targetIterator =
           renameAttributeTo.getValues().iterator();
      while (sourceIterator.hasNext())
      {
        transformations.add(new RenameAttributeTransformation(null,
             sourceIterator.next(), targetIterator.next(), true));
      }
    }

    if (moveSubtreeFrom.isPresent())
    {
      if (moveSubtreeFrom.getNumOccurrences() !=
          moveSubtreeTo.getNumOccurrences())
      {
        throw new ArgumentException(ERR_LDAPSEARCH_MOVE_SUBTREE_MISMATCH.get());
      }

      final Iterator<DN> sourceIterator =
           moveSubtreeFrom.getValues().iterator();
      final Iterator<DN> targetIterator = moveSubtreeTo.getValues().iterator();
      while (sourceIterator.hasNext())
      {
        transformations.add(new MoveSubtreeTransformation(sourceIterator.next(),
             targetIterator.next()));
      }
    }

    if (! transformations.isEmpty())
    {
      entryTransformations = transformations;
    }


    // Create the output handler.
    final String outputFormatStr =
         StaticUtils.toLowerCase(outputFormat.getValue());
    if (outputFormatStr.equals("json"))
    {
      outputHandler = new JSONLDAPSearchOutputHandler(this);
    }
    else if (outputFormatStr.equals("csv") ||
             outputFormatStr.equals("multi-valued-csv") ||
             outputFormatStr.equals("tab-delimited") ||
             outputFormatStr.equals("multi-valued-tab-delimited"))
    {
      // These output formats cannot be used with the --ldapURLFile argument.
      if (ldapURLFile.isPresent())
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_OUTPUT_FORMAT_NOT_SUPPORTED_WITH_URLS.get(
                  outputFormat.getValue(), ldapURLFile.getIdentifierString()));
      }

      // These output formats require the requested attributes to be specified
      // via the --requestedAttribute argument rather than as unnamed trailing
      // arguments.
      final List<String> requestedAttributes = requestedAttribute.getValues();
      if ((requestedAttributes == null) || requestedAttributes.isEmpty())
      {
        throw new ArgumentException(
             ERR_LDAPSEARCH_OUTPUT_FORMAT_REQUIRES_REQUESTED_ATTR_ARG.get(
                  outputFormat.getValue(),
                  requestedAttribute.getIdentifierString()));
      }

      switch (trailingArgs.size())
      {
        case 0:
          // This is fine.
          break;

        case 1:
          // Make sure that the trailing argument is a filter rather than a
          // requested attribute.  It's sufficient to ensure that neither the
          // filter nor filterFile argument was provided.
          if (filter.isPresent() || filterFile.isPresent())
          {
            throw new ArgumentException(
                 ERR_LDAPSEARCH_OUTPUT_FORMAT_REQUIRES_REQUESTED_ATTR_ARG.get(
                      outputFormat.getValue(),
                      requestedAttribute.getIdentifierString()));
          }
          break;

        default:
          throw new ArgumentException(
               ERR_LDAPSEARCH_OUTPUT_FORMAT_REQUIRES_REQUESTED_ATTR_ARG.get(
                    outputFormat.getValue(),
                    requestedAttribute.getIdentifierString()));
      }

      final OutputFormat format;
      final boolean includeAllValues;
      switch (outputFormatStr)
      {
        case "multi-valued-csv":
          format = OutputFormat.CSV;
          includeAllValues = true;
          break;
        case "tab-delimited":
          format = OutputFormat.TAB_DELIMITED_TEXT;
          includeAllValues = false;
          break;
        case "multi-valued-tab-delimited":
          format = OutputFormat.TAB_DELIMITED_TEXT;
          includeAllValues = true;
          break;
        case "csv":
        default:
          format = OutputFormat.CSV;
          includeAllValues = false;
          break;
      }


      outputHandler = new ColumnFormatterLDAPSearchOutputHandler(this,
           format, requestedAttributes, WRAP_COLUMN, includeAllValues);
    }
    else if (outputFormatStr.equals("dns-only"))
    {
      outputHandler = new DNsOnlyLDAPSearchOutputHandler(this);
    }
    else if (outputFormatStr.equals("values-only"))
    {
      outputHandler = new ValuesOnlyLDAPSearchOutputHandler(this);
    }
    else
    {
      outputHandler = new LDIFLDAPSearchOutputHandler(this, WRAP_COLUMN);
    }
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
    // If we should encrypt the output, then get the encryption passphrase.
    if (encryptOutput.isPresent())
    {
      if (encryptionPassphraseFile.isPresent())
      {
        try
        {
          encryptionPassphrase = ToolUtils.readEncryptionPassphraseFromFile(
               encryptionPassphraseFile.getValue());
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN, e.getMessage());
          return e.getResultCode();
        }
      }
      else
      {
        try
        {
          encryptionPassphrase = ToolUtils.promptForEncryptionPassphrase(false,
               true, getOut(), getErr());
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN, e.getMessage());
          return e.getResultCode();
        }
      }
    }


    // If we should use an output file, then set that up now.  Otherwise, write
    // the header to standard output.
    if (outputFile.isPresent())
    {
      if (! separateOutputFilePerSearch.isPresent())
      {
        try
        {
          OutputStream s = new FileOutputStream(outputFile.getValue());

          if (encryptOutput.isPresent())
          {
            s = new PassphraseEncryptedOutputStream(encryptionPassphrase, s);
          }

          if (compressOutput.isPresent())
          {
            s = new GZIPOutputStream(s);
          }

          if (teeResultsToStandardOut.isPresent())
          {
            outStream = new PrintStream(new TeeOutputStream(s, getOut()));
          }
          else
          {
            outStream = new PrintStream(s);
          }
          errStream = outStream;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN, ERR_LDAPSEARCH_CANNOT_OPEN_OUTPUT_FILE.get(
               outputFile.getValue().getAbsolutePath(),
               StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }

        outputHandler.formatHeader();
      }
    }
    else
    {
      outputHandler.formatHeader();
    }


    // Examine the arguments to determine the sets of controls to use for each
    // type of request.
    final List<Control> searchControls = getSearchControls();


    // If appropriate, ensure that any search result entries that include
    // base64-encoded attribute values will also include comments that attempt
    // to provide a human-readable representation of that value.
    final boolean originalCommentAboutBase64EncodedValues =
         LDIFWriter.commentAboutBase64EncodedValues();
    LDIFWriter.setCommentAboutBase64EncodedValues(
         ! suppressBase64EncodedValueComments.isPresent());


    LDAPConnectionPool pool = null;
    try
    {
      // Create a connection pool that will be used to communicate with the
      // directory server.
      if (! dryRun.isPresent())
      {
        try
        {
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

          pool = getConnectionPool(1, 1, 0, p, null, true,
               new ReportBindResultLDAPConnectionPoolHealthCheck(this, true,
                    false));
        }
        catch (final LDAPException le)
        {
          // This shouldn't happen since the pool won't throw an exception if an
          // attempt to create an initial connection fails.
          Debug.debugException(le);
          commentToErr(ERR_LDAPSEARCH_CANNOT_CREATE_CONNECTION_POOL.get(
               StaticUtils.getExceptionMessage(le)));
          return le.getResultCode();
        }

        if (retryFailedOperations.isPresent())
        {
          pool.setRetryFailedOperationsDueToInvalidConnections(true);
        }
      }


      // If appropriate, create a rate limiter.
      final FixedRateBarrier rateLimiter;
      if (ratePerSecond.isPresent())
      {
        rateLimiter = new FixedRateBarrier(1000L, ratePerSecond.getValue());
      }
      else
      {
        rateLimiter = null;
      }


      // If one or more LDAP URL files are provided, then construct search
      // requests from those URLs.
      if (ldapURLFile.isPresent())
      {
        return searchWithLDAPURLs(pool, rateLimiter, searchControls);
      }


      // Get the set of requested attributes, as a combination of the
      // requestedAttribute argument values and any trailing arguments.
      final ArrayList<String> attrList = new ArrayList<>(10);
      if (requestedAttribute.isPresent())
      {
        attrList.addAll(requestedAttribute.getValues());
      }

      final List<String> trailingArgs = parser.getTrailingArguments();
      if (! trailingArgs.isEmpty())
      {
        final Iterator<String> trailingArgIterator = trailingArgs.iterator();
        if (! (filter.isPresent() || filterFile.isPresent()))
        {
          trailingArgIterator.next();
        }

        while (trailingArgIterator.hasNext())
        {
          attrList.add(trailingArgIterator.next());
        }
      }

      final String[] attributes = new String[attrList.size()];
      attrList.toArray(attributes);


      // If either or both the filter or filterFile arguments are provided, then
      // use them to get the filters to process.  Otherwise, the first trailing
      // argument should be a filter.
      ResultCode resultCode = ResultCode.SUCCESS;
      if (filter.isPresent() || filterFile.isPresent())
      {
        if (filter.isPresent())
        {
          for (final Filter f : filter.getValues())
          {
            final ResultCode rc = searchWithFilter(pool, f, attributes,
                 rateLimiter, searchControls);
            if (rc != ResultCode.SUCCESS)
            {
              if (resultCode == ResultCode.SUCCESS)
              {
                resultCode = rc;
              }

              if (! continueOnError.isPresent())
              {
                return resultCode;
              }
            }
          }
        }

        if (filterFile.isPresent())
        {
          final ResultCode rc = searchWithFilterFile(pool, attributes,
               rateLimiter, searchControls);
          if (rc != ResultCode.SUCCESS)
          {
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = rc;
            }

            if (! continueOnError.isPresent())
            {
              return resultCode;
            }
          }
        }
      }
      else
      {
        final Filter f;
        try
        {
          final String filterStr =
               parser.getTrailingArguments().iterator().next();
          f = Filter.create(filterStr);
        }
        catch (final LDAPException le)
        {
          // This should never happen.
          Debug.debugException(le);
          displayResult(le.toLDAPResult());
          return le.getResultCode();
        }

        resultCode =
             searchWithFilter(pool, f, attributes, rateLimiter, searchControls);
      }

      return resultCode;
    }
    finally
    {
      if (pool != null)
      {
        try
        {
          pool.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      if (outStream != null)
      {
        try
        {
          outStream.close();
          outStream = null;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      if (errStream != null)
      {
        try
        {
          errStream.close();
          errStream = null;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }

      LDIFWriter.setCommentAboutBase64EncodedValues(
           originalCommentAboutBase64EncodedValues);
    }
  }



  /**
   * Processes a set of searches using LDAP URLs read from one or more files.
   *
   * @param  pool            The connection pool to use to communicate with the
   *                         directory server.
   * @param  rateLimiter     An optional fixed-rate barrier that can be used for
   *                         request rate limiting.
   * @param  searchControls  The set of controls to include in search requests.
   *
   * @return  A result code indicating the result of the processing.
   */
  @NotNull()
  private ResultCode searchWithLDAPURLs(@NotNull final LDAPConnectionPool pool,
               @Nullable final FixedRateBarrier rateLimiter,
               @NotNull final List<Control> searchControls)
  {
    ResultCode resultCode = ResultCode.SUCCESS;
    for (final File f : ldapURLFile.getValues())
    {
      BufferedReader reader = null;

      try
      {
        reader = new BufferedReader(new FileReader(f));
        while (true)
        {
          final String line = reader.readLine();
          if (line == null)
          {
            break;
          }

          if ((line.length() == 0) || line.startsWith("#"))
          {
            continue;
          }

          final LDAPURL url;
          try
          {
            url = new LDAPURL(line);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);

            commentToErr(ERR_LDAPSEARCH_MALFORMED_LDAP_URL.get(
                 f.getAbsolutePath(), line));
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = le.getResultCode();
            }

            if (continueOnError.isPresent())
            {
              continue;
            }
            else
            {
              return resultCode;
            }
          }

          final SearchRequest searchRequest = new SearchRequest(
               new LDAPSearchListener(outputHandler, entryTransformations),
               url.getBaseDN().toString(), url.getScope(), derefPolicy,
               sizeLimit.getValue(), timeLimitSeconds.getValue(),
               typesOnly.isPresent(), url.getFilter(), url.getAttributes());
          final ResultCode rc =
               doSearch(pool, searchRequest, rateLimiter, searchControls);
          if (rc != ResultCode.SUCCESS)
          {
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = rc;
            }

            if (! continueOnError.isPresent())
            {
              return resultCode;
            }
          }
        }
      }
      catch (final IOException ioe)
      {
        commentToErr(ERR_LDAPSEARCH_CANNOT_READ_LDAP_URL_FILE.get(
             f.getAbsolutePath(), StaticUtils.getExceptionMessage(ioe)));
        return ResultCode.LOCAL_ERROR;
      }
      finally
      {
        if (reader != null)
        {
          try
          {
            reader.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }
    }

    return resultCode;
  }



  /**
   * Processes a set of searches using filters read from one or more files.
   *
   * @param  pool            The connection pool to use to communicate with the
   *                         directory server.
   * @param  attributes      The set of attributes to request that the server
   *                         include in matching entries.
   * @param  rateLimiter     An optional fixed-rate barrier that can be used for
   *                         request rate limiting.
   * @param  searchControls  The set of controls to include in search requests.
   *
   * @return  A result code indicating the result of the processing.
   */
  @NotNull()
  private ResultCode searchWithFilterFile(
               @NotNull final LDAPConnectionPool pool,
               @NotNull final String[] attributes,
               @Nullable final FixedRateBarrier rateLimiter,
               @NotNull final List<Control> searchControls)
  {
    ResultCode resultCode = ResultCode.SUCCESS;
    for (final File f : filterFile.getValues())
    {
      FilterFileReader reader = null;

      try
      {
        reader = new FilterFileReader(f);
        while (true)
        {
          final Filter searchFilter;
          try
          {
            searchFilter = reader.readFilter();
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            commentToErr(ERR_LDAPSEARCH_MALFORMED_FILTER.get(
                 f.getAbsolutePath(), le.getMessage()));
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = le.getResultCode();
            }

            if (continueOnError.isPresent())
            {
              continue;
            }
            else
            {
              return resultCode;
            }
          }

          if (searchFilter == null)
          {
            break;
          }

          final ResultCode rc = searchWithFilter(pool, searchFilter, attributes,
               rateLimiter, searchControls);
          if (rc != ResultCode.SUCCESS)
          {
            if (resultCode == ResultCode.SUCCESS)
            {
              resultCode = rc;
            }

            if (! continueOnError.isPresent())
            {
              return resultCode;
            }
          }
        }
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        commentToErr(ERR_LDAPSEARCH_CANNOT_READ_FILTER_FILE.get(
             f.getAbsolutePath(), StaticUtils.getExceptionMessage(ioe)));
        return ResultCode.LOCAL_ERROR;
      }
      finally
      {
        if (reader != null)
        {
          try
          {
            reader.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }
    }

    return resultCode;
  }



  /**
   * Processes a search using the provided filter.
   *
   * @param  pool            The connection pool to use to communicate with the
   *                         directory server.
   * @param  filter          The filter to use for the search.
   * @param  attributes      The set of attributes to request that the server
   *                         include in matching entries.
   * @param  rateLimiter     An optional fixed-rate barrier that can be used for
   *                         request rate limiting.
   * @param  searchControls  The set of controls to include in search requests.
   *
   * @return  A result code indicating the result of the processing.
   */
  @NotNull()
  private ResultCode searchWithFilter(@NotNull final LDAPConnectionPool pool,
               @NotNull final Filter filter,
               @NotNull final String[] attributes,
               @Nullable final FixedRateBarrier rateLimiter,
               @NotNull final List<Control> searchControls)
  {
    final String baseDNString;
    if (baseDN.isPresent())
    {
      baseDNString = baseDN.getStringValue();
    }
    else
    {
      baseDNString = "";
    }

    final SearchRequest searchRequest = new SearchRequest(
         new LDAPSearchListener(outputHandler, entryTransformations),
         baseDNString, scope.getValue(), derefPolicy, sizeLimit.getValue(),
         timeLimitSeconds.getValue(), typesOnly.isPresent(), filter,
         attributes);
    return doSearch(pool, searchRequest, rateLimiter, searchControls);
  }



  /**
   * Processes a search with the provided information.
   *
   * @param  pool            The connection pool to use to communicate with the
   *                         directory server.
   * @param  searchRequest   The search request to process.
   * @param  rateLimiter     An optional fixed-rate barrier that can be used for
   *                         request rate limiting.
   * @param  searchControls  The set of controls to include in search requests.
   *
   * @return  A result code indicating the result of the processing.
   */
  @NotNull()
  private ResultCode doSearch(@NotNull final LDAPConnectionPool pool,
                              @NotNull final SearchRequest searchRequest,
                              @Nullable final FixedRateBarrier rateLimiter,
                              @NotNull final List<Control> searchControls)
  {
    if (separateOutputFilePerSearch.isPresent())
    {
      try
      {
        final String path = outputFile.getValue().getAbsolutePath() + '.' +
             outputFileCounter.getAndIncrement();

        OutputStream s = new FileOutputStream(path);

        if (encryptOutput.isPresent())
        {
          s = new PassphraseEncryptedOutputStream(encryptionPassphrase, s);
        }

        if (compressOutput.isPresent())
        {
          s = new GZIPOutputStream(s);
        }

        if (teeResultsToStandardOut.isPresent())
        {
          outStream = new PrintStream(new TeeOutputStream(s, getOut()));
        }
        else
        {
          outStream = new PrintStream(s);
        }
        errStream = outStream;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN, ERR_LDAPSEARCH_CANNOT_OPEN_OUTPUT_FILE.get(
             outputFile.getValue().getAbsolutePath(),
             StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }

      outputHandler.formatHeader();
    }

    try
    {
      if (rateLimiter != null)
      {
        rateLimiter.await();
      }


      ASN1OctetString pagedResultsCookie = null;
      boolean multiplePages = false;
      long totalEntries = 0;
      long totalReferences = 0;

      SearchResult searchResult;
      try
      {
        while (true)
        {
          searchRequest.setControls(searchControls);
          if (simplePageSize.isPresent())
          {
            searchRequest.addControl(new SimplePagedResultsControl(
                 simplePageSize.getValue(), pagedResultsCookie));
          }

          if (dryRun.isPresent())
          {
            searchResult = new SearchResult(-1, ResultCode.SUCCESS,
                 INFO_LDAPSEARCH_DRY_RUN_REQUEST_NOT_SENT.get(
                      dryRun.getIdentifierString(),
                      String.valueOf(searchRequest)),
                 null, null, 0, 0, null);
            break;
          }
          else
          {
            if (! terse.isPresent())
            {
              if (verbose.isPresent() || persistentSearch.isPresent() ||
                  filterFile.isPresent() || ldapURLFile.isPresent() ||
                  (filter.isPresent() && (filter.getNumOccurrences() > 1)))
              {
                commentToOut(INFO_LDAPSEARCH_SENDING_SEARCH_REQUEST.get(
                     String.valueOf(searchRequest)));
              }
            }
            searchResult = pool.search(searchRequest);
          }

          if (searchResult.getEntryCount() > 0)
          {
            totalEntries += searchResult.getEntryCount();
          }

          if (searchResult.getReferenceCount() > 0)
          {
            totalReferences += searchResult.getReferenceCount();
          }

          if (simplePageSize.isPresent())
          {
            final SimplePagedResultsControl pagedResultsControl;
            try
            {
              pagedResultsControl = SimplePagedResultsControl.get(searchResult);
              if (pagedResultsControl == null)
              {
                throw new LDAPSearchException(new SearchResult(
                     searchResult.getMessageID(), ResultCode.CONTROL_NOT_FOUND,
                     ERR_LDAPSEARCH_MISSING_PAGED_RESULTS_RESPONSE_CONTROL.
                          get(),
                     searchResult.getMatchedDN(),
                     searchResult.getReferralURLs(),
                     searchResult.getSearchEntries(),
                     searchResult.getSearchReferences(),
                     searchResult.getEntryCount(),
                     searchResult.getReferenceCount(),
                     searchResult.getResponseControls()));
              }

              if (pagedResultsControl.moreResultsToReturn())
              {
                if (verbose.isPresent())
                {
                  commentToOut(
                       INFO_LDAPSEARCH_INTERMEDIATE_PAGED_SEARCH_RESULT.get());
                  displayResult(searchResult);
                }

                multiplePages = true;
                pagedResultsCookie = pagedResultsControl.getCookie();
              }
              else
              {
                break;
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
              throw new LDAPSearchException(new SearchResult(
                   searchResult.getMessageID(), ResultCode.CONTROL_NOT_FOUND,
                   ERR_LDAPSEARCH_CANNOT_DECODE_PAGED_RESULTS_RESPONSE_CONTROL.
                        get(StaticUtils.getExceptionMessage(le)),
                   searchResult.getMatchedDN(), searchResult.getReferralURLs(),
                   searchResult.getSearchEntries(),
                   searchResult.getSearchReferences(),
                   searchResult.getEntryCount(),
                   searchResult.getReferenceCount(),
                   searchResult.getResponseControls()));
            }
          }
          else
          {
            break;
          }
        }
      }
      catch (final LDAPSearchException lse)
      {
        Debug.debugException(lse);
        searchResult = lse.toLDAPResult();

        if (searchResult.getEntryCount() > 0)
        {
          totalEntries += searchResult.getEntryCount();
        }

        if (searchResult.getReferenceCount() > 0)
        {
          totalReferences += searchResult.getReferenceCount();
        }
      }

      if ((searchResult.getResultCode() != ResultCode.SUCCESS) ||
          (searchResult.getDiagnosticMessage() != null) ||
          (! terse.isPresent()))
      {
        displayResult(searchResult);
      }

      if (multiplePages && (! terse.isPresent()))
      {
        commentToOut(INFO_LDAPSEARCH_TOTAL_SEARCH_ENTRIES.get(totalEntries));

        if (totalReferences > 0)
        {
          commentToOut(INFO_LDAPSEARCH_TOTAL_SEARCH_REFERENCES.get(
               totalReferences));
        }
      }

      if (countEntries.isPresent())
      {
        return ResultCode.valueOf((int) Math.min(totalEntries, 255));
      }
      else if (requireMatch.isPresent() && (totalEntries == 0))
      {
        return ResultCode.NO_RESULTS_RETURNED;
      }
      else
      {
        return searchResult.getResultCode();
      }
    }
    finally
    {
      if (separateOutputFilePerSearch.isPresent())
      {
        try
        {
          outStream.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }

        outStream = null;
        errStream = null;
      }
    }
  }



  /**
   * Retrieves a list of the controls that should be used when processing search
   * operations.
   *
   * @return  A list of the controls that should be used when processing search
   *          operations.
   *
   * @throws  LDAPException  If a problem is encountered while generating the
   *                         controls for a search request.
   */
  @NotNull()
  private List<Control> getSearchControls()
  {
    final ArrayList<Control> controls = new ArrayList<>(10);

    if (searchControl.isPresent())
    {
      controls.addAll(searchControl.getValues());
    }

    if (joinRequestControl != null)
    {
      controls.add(joinRequestControl);
    }

    if (matchedValuesRequestControl != null)
    {
      controls.add(matchedValuesRequestControl);
    }

    if (matchingEntryCountRequestControl != null)
    {
      controls.add(matchingEntryCountRequestControl);
    }

    if (overrideSearchLimitsRequestControl != null)
    {
      controls.add(overrideSearchLimitsRequestControl);
    }

    if (persistentSearchRequestControl != null)
    {
      controls.add(persistentSearchRequestControl);
    }

    if (sortRequestControl != null)
    {
      controls.add(sortRequestControl);
    }

    if (vlvRequestControl != null)
    {
      controls.add(vlvRequestControl);
    }

    controls.addAll(routeToBackendSetRequestControls);

    if (accountUsable.isPresent())
    {
      controls.add(new AccountUsableRequestControl(true));
    }

    if (getBackendSetID.isPresent())
    {
      controls.add(new GetBackendSetIDRequestControl(false));
    }

    if (getServerID.isPresent())
    {
      controls.add(new GetServerIDRequestControl(false));
    }

    if (includeReplicationConflictEntries.isPresent())
    {
      controls.add(new ReturnConflictEntriesRequestControl(true));
    }

    if (includeSoftDeletedEntries.isPresent())
    {
      final String valueStr =
           StaticUtils.toLowerCase(includeSoftDeletedEntries.getValue());
      if (valueStr.equals("with-non-deleted-entries"))
      {
        controls.add(new SoftDeletedEntryAccessRequestControl(true, true,
             false));
      }
      else if (valueStr.equals("without-non-deleted-entries"))
      {
        controls.add(new SoftDeletedEntryAccessRequestControl(true, false,
             false));
      }
      else
      {
        controls.add(new SoftDeletedEntryAccessRequestControl(true, false,
             true));
      }
    }

    if (draftLDUPSubentries.isPresent())
    {
      controls.add(new DraftLDUPSubentriesRequestControl(true));
    }

    if (rfc3672Subentries.isPresent())
    {
      controls.add(new RFC3672SubentriesRequestControl(
           rfc3672Subentries.getValue()));
    }

    if (manageDsaIT.isPresent())
    {
      controls.add(new ManageDsaITRequestControl(true));
    }

    if (realAttributesOnly.isPresent())
    {
      controls.add(new RealAttributesOnlyRequestControl(true));
    }

    if (routeToServer.isPresent())
    {
      controls.add(new RouteToServerRequestControl(false,
           routeToServer.getValue(), false, false, false));
    }

    if (virtualAttributesOnly.isPresent())
    {
      controls.add(new VirtualAttributesOnlyRequestControl(true));
    }

    if (excludeBranch.isPresent())
    {
      final ArrayList<String> dns =
           new ArrayList<>(excludeBranch.getValues().size());
      for (final DN dn : excludeBranch.getValues())
      {
        dns.add(dn.toString());
      }
      controls.add(new ExcludeBranchRequestControl(true, dns));
    }

    if (assertionFilter.isPresent())
    {
      controls.add(new AssertionRequestControl(
           assertionFilter.getValue(), true));
    }

    if (getEffectiveRightsAuthzID.isPresent())
    {
      final String[] attributes;
      if (getEffectiveRightsAttribute.isPresent())
      {
        attributes = new String[getEffectiveRightsAttribute.getValues().size()];
        for (int i=0; i < attributes.length; i++)
        {
          attributes[i] = getEffectiveRightsAttribute.getValues().get(i);
        }
      }
      else
      {
        attributes = StaticUtils.NO_STRINGS;
      }

      controls.add(new GetEffectiveRightsRequestControl(true,
           getEffectiveRightsAuthzID.getValue(), attributes));
    }

    if (operationPurpose.isPresent())
    {
      controls.add(new OperationPurposeRequestControl(true, "ldapsearch",
           Version.NUMERIC_VERSION_STRING, "LDAPSearch.getSearchControls",
           operationPurpose.getValue()));
    }

    if (proxyAs.isPresent())
    {
      controls.add(new ProxiedAuthorizationV2RequestControl(
           proxyAs.getValue()));
    }

    if (proxyV1As.isPresent())
    {
      controls.add(new ProxiedAuthorizationV1RequestControl(
           proxyV1As.getValue()));
    }

    if (suppressOperationalAttributeUpdates.isPresent())
    {
      final EnumSet<SuppressType> suppressTypes =
           EnumSet.noneOf(SuppressType.class);
      for (final String s : suppressOperationalAttributeUpdates.getValues())
      {
        if (s.equalsIgnoreCase("last-access-time"))
        {
          suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
        }
        else if (s.equalsIgnoreCase("last-login-time"))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
        }
        else if (s.equalsIgnoreCase("last-login-ip"))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_IP);
        }
      }

      controls.add(new SuppressOperationalAttributeUpdateRequestControl(
           suppressTypes));
    }

    if (rejectUnindexedSearch.isPresent())
    {
      controls.add(new RejectUnindexedSearchRequestControl());
    }

    if (permitUnindexedSearch.isPresent())
    {
      controls.add(new PermitUnindexedSearchRequestControl());
    }

    return controls;
  }



  /**
   * Displays information about the provided result, including special
   * processing for a number of supported response controls.
   *
   * @param  result  The result to examine.
   */
  private void displayResult(@NotNull final LDAPResult result)
  {
    outputHandler.formatResult(result);
  }



  /**
   * Writes the provided message to the output stream.
   *
   * @param  message  The message to be written.
   */
  void writeOut(@NotNull final String message)
  {
    if (outStream == null)
    {
      out(message);
    }
    else
    {
      outStream.println(message);
    }
  }



  /**
   * Writes the provided message to the error stream.
   *
   * @param  message  The message to be written.
   */
  private void writeErr(@NotNull final String message)
  {
    if (errStream == null)
    {
      err(message);
    }
    else
    {
      errStream.println(message);
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
    if (terse.isPresent())
    {
      return;
    }

    for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
    {
      writeOut("# " + line);
    }
  }



  /**
   * Writes a line-wrapped, commented version of the provided message to
   * standard error.
   *
   * @param  message  The message to be written.
   */
  private void commentToErr(@NotNull final String message)
  {
    for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
    {
      writeErr("# " + line);
    }
  }



  /**
   * Retrieves the tool's output stream.
   *
   * @return  The tool's output stream.
   */
  @NotNull()
  PrintStream getOutStream()
  {
    if (outStream == null)
    {
      return getOut();
    }
    else
    {
      return outStream;
    }
  }



  /**
   * Retrieves the tool's error stream.
   *
   * @return  The tool's error stream.
   */
  @NotNull()
  PrintStream getErrStream()
  {
    if (errStream == null)
    {
      return getErr();
    }
    else
    {
      return errStream;
    }
  }



  /**
   * Sets the output handler that should be used by this tool  This is primarily
   * intended for testing purposes.
   *
   * @param  outputHandler  The output handler that should be used by this tool.
   */
  void setOutputHandler(@NotNull final LDAPSearchOutputHandler outputHandler)
  {
    this.outputHandler = outputHandler;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    outputHandler.formatUnsolicitedNotification(connection, notification);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));

    String[] args =
    {
      "--hostname", "directory.example.com",
      "--port", "389",
      "--bindDN", "uid=jdoe,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "ou=People,dc=example,dc=com",
      "--scope", "sub",
      "(uid=jqpublic)",
      "givenName",
      "sn",
      "mail"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_1.get());


    args = new String[]
    {
      "--hostname", "directory.example.com",
      "--port", "636",
      "--useSSL",
      "--saslOption", "mech=PLAIN",
      "--saslOption", "authID=u:jdoe",
      "--bindPasswordFile", "/path/to/password/file",
      "--baseDN", "ou=People,dc=example,dc=com",
      "--scope", "sub",
      "--filterFile", "/path/to/filter/file",
      "--outputFile", "/path/to/base/output/file",
      "--separateOutputFilePerSearch",
      "--requestedAttribute", "*",
      "--requestedAttribute", "+"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_2.get());


    args = new String[]
    {
      "--hostname", "directory.example.com",
      "--port", "389",
      "--useStartTLS",
      "--trustStorePath", "/path/to/truststore/file",
      "--baseDN", "",
      "--scope", "base",
      "--outputFile", "/path/to/output/file",
      "--teeResultsToStandardOut",
      "(objectClass=*)",
      "*",
      "+"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_3.get());


    args = new String[]
    {
      "--hostname", "directory.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--baseDN", "dc=example,dc=com",
      "--scope", "sub",
      "--outputFile", "/path/to/output/file",
      "--simplePageSize", "100",
      "(objectClass=*)",
      "*",
      "+"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_4.get());


    args = new String[]
    {
      "--hostname", "directory.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--baseDN", "dc=example,dc=com",
      "--scope", "sub",
      "(&(givenName=John)(sn=Doe))",
      "debugsearchindex"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_5.get());

    return examples;
  }
}
