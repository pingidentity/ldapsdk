/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;

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
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.MatchedValuesFilter;
import com.unboundid.ldap.sdk.controls.MatchedValuesRequestControl;
import com.unboundid.ldap.sdk.controls.PersistentSearchChangeType;
import com.unboundid.ldap.sdk.controls.PersistentSearchRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.controls.SubentriesRequestControl;
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
            GetEffectiveRightsRequestControl;
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
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RealAttributesOnlyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReturnConflictEntriesRequestControl;
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
import com.unboundid.util.OutputFormat;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TeeOutputStream;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
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
 * Alcatel-Lucent 8661 server products.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  private BooleanArgument accountUsable = null;
  private BooleanArgument authorizationIdentity = null;
  private BooleanArgument continueOnError = null;
  private BooleanArgument countEntries = null;
  private BooleanArgument dontWrap = null;
  private BooleanArgument dryRun = null;
  private BooleanArgument followReferrals = null;
  private BooleanArgument hideRedactedValueCount = null;
  private BooleanArgument getUserResourceLimits = null;
  private BooleanArgument includeReplicationConflictEntries = null;
  private BooleanArgument includeSubentries = null;
  private BooleanArgument joinRequireMatch = null;
  private BooleanArgument manageDsaIT = null;
  private BooleanArgument realAttributesOnly = null;
  private BooleanArgument retryFailedOperations = null;
  private BooleanArgument separateOutputFilePerSearch = null;
  private BooleanArgument suppressBase64EncodedValueComments = null;
  private BooleanArgument teeResultsToStandardOut = null;
  private BooleanArgument useAdministrativeSession = null;
  private BooleanArgument usePasswordPolicyControl = null;
  private BooleanArgument terse = null;
  private BooleanArgument typesOnly = null;
  private BooleanArgument verbose = null;
  private BooleanArgument virtualAttributesOnly = null;
  private ControlArgument bindControl = null;
  private ControlArgument searchControl = null;
  private DNArgument baseDN = null;
  private DNArgument excludeBranch = null;
  private DNArgument moveSubtreeFrom = null;
  private DNArgument moveSubtreeTo = null;
  private DNArgument proxyV1As = null;
  private FileArgument filterFile = null;
  private FileArgument ldapURLFile = null;
  private FileArgument outputFile = null;
  private FilterArgument assertionFilter = null;
  private FilterArgument filter = null;
  private FilterArgument joinFilter = null;
  private FilterArgument matchedValuesFilter = null;
  private IntegerArgument joinSizeLimit = null;
  private IntegerArgument ratePerSecond = null;
  private IntegerArgument scrambleRandomSeed = null;
  private IntegerArgument simplePageSize = null;
  private IntegerArgument sizeLimit = null;
  private IntegerArgument timeLimitSeconds = null;
  private IntegerArgument wrapColumn = null;
  private ScopeArgument joinScope = null;
  private ScopeArgument scope = null;
  private StringArgument dereferencePolicy = null;
  private StringArgument excludeAttribute = null;
  private StringArgument getAuthorizationEntryAttribute = null;
  private StringArgument getEffectiveRightsAttribute = null;
  private StringArgument getEffectiveRightsAuthzID = null;
  private StringArgument includeSoftDeletedEntries = null;
  private StringArgument joinBaseDN = null;
  private StringArgument joinRequestedAttribute = null;
  private StringArgument joinRule = null;
  private StringArgument matchingEntryCountControl = null;
  private StringArgument operationPurpose = null;
  private StringArgument outputFormat = null;
  private StringArgument persistentSearch = null;
  private StringArgument proxyAs = null;
  private StringArgument redactAttribute = null;
  private StringArgument renameAttributeFrom = null;
  private StringArgument renameAttributeTo = null;
  private StringArgument requestedAttribute = null;
  private StringArgument scrambleAttribute = null;
  private StringArgument scrambleJSONField = null;
  private StringArgument sortOrder = null;
  private StringArgument suppressOperationalAttributeUpdates = null;
  private StringArgument virtualListView = null;

  // The argument parser used by this tool.
  private volatile ArgumentParser parser = null;

  // Controls that should be sent to the server but need special validation.
  private volatile JoinRequestControl joinRequestControl = null;
  private volatile MatchedValuesRequestControl
       matchedValuesRequestControl = null;
  private volatile MatchingEntryCountRequestControl
       matchingEntryCountRequestControl = null;
  private volatile PersistentSearchRequestControl
       persistentSearchRequestControl = null;
  private volatile ServerSideSortRequestControl sortRequestControl = null;
  private volatile VirtualListViewRequestControl vlvRequestControl = null;

  // Other values decoded from arguments.
  private volatile DereferencePolicy derefPolicy = null;

  // The print streams used for standard output and error.
  private final AtomicLong outputFileCounter = new AtomicLong(1);
  private volatile PrintStream errStream = null;
  private volatile PrintStream outStream = null;

  // The output handler for this tool.
  private volatile LDAPSearchOutputHandler outputHandler =
       new LDIFLDAPSearchOutputHandler(this, WRAP_COLUMN);

  // The list of entry transformations to apply.
  private volatile List<EntryTransformation> entryTransformations = null;



  /**
   * Runs this tool with the provided command-line arguments.  It will use the
   * JVM-default streams for standard input, output, and error.
   *
   * @param  args  The command-line arguments to provide to this program.
   */
  public static void main(final String... args)
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
  public static ResultCode main(final OutputStream out, final OutputStream err,
                                final String... args)
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
  public LDAPSearch(final OutputStream out, final OutputStream err)
  {
    super(out, err);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "ldapsearch";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return INFO_LDAPSEARCH_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
  protected Set<Character> getSuppressedShortIdentifiers()
  {
    return Collections.singleton('T');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
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

    final LinkedHashSet<String> derefAllowedValues =
         new LinkedHashSet<String>(4);
    derefAllowedValues.add("never");
    derefAllowedValues.add("always");
    derefAllowedValues.add("search");
    derefAllowedValues.add("find");
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

    final LinkedHashSet<String> outputFormatAllowedValues =
         new LinkedHashSet<String>(4);
    outputFormatAllowedValues.add("ldif");
    outputFormatAllowedValues.add("json");
    outputFormatAllowedValues.add("csv");
    outputFormatAllowedValues.add("tab-delimited");
    outputFormat = new StringArgument(null, "outputFormat", false, 1,
         "{ldif|json|csv|tab-delimited}",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_OUTPUT_FORMAT.get(
              requestedAttribute.getIdentifierString(),
              ldapURLFile.getIdentifierString()),
         outputFormatAllowedValues, "ldif");
    outputFormat.addLongIdentifier("output-format", true);
    outputFormat.setArgumentGroupName(INFO_LDAPSEARCH_ARG_GROUP_DATA.get());
    parser.addArgument(outputFormat);

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

    getAuthorizationEntryAttribute = new StringArgument(null,
         "getAuthorizationEntryAttribute", false, 0,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_AUTHZ_ENTRY_ATTR.get());
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authorization-entry-attribute", true);
    getAuthorizationEntryAttribute.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getAuthorizationEntryAttribute);

    getUserResourceLimits = new BooleanArgument(null, "getUserResourceLimits",
         1, INFO_LDAPSEARCH_ARG_DESCRIPTION_GET_USER_RESOURCE_LIMITS.get());
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits", true);
    getUserResourceLimits.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(getUserResourceLimits);

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

    includeReplicationConflictEntries = new BooleanArgument(null,
         "includeReplicationConflictEntries", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_REPL_CONFLICTS.get());
    includeReplicationConflictEntries.addLongIdentifier(
         "include-replication-conflict-entries", true);
    includeReplicationConflictEntries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(includeReplicationConflictEntries);

    final LinkedHashSet<String> softDeleteAllowedValues =
         new LinkedHashSet<String>(3);
    softDeleteAllowedValues.add("with-non-deleted-entries");
    softDeleteAllowedValues.add("without-non-deleted-entries");
    softDeleteAllowedValues.add("deleted-entries-in-undeleted-form");
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

    includeSubentries = new BooleanArgument(null, "includeSubentries", 1,
         INFO_LDAPSEARCH_ARG_DESCRIPTION_INCLUDE_SUBENTRIES.get());
    includeSubentries.addLongIdentifier("includeLDAPSubentries", true);
    includeSubentries.addLongIdentifier("include-subentries", true);
    includeSubentries.addLongIdentifier("include-ldap-subentries", true);
    includeSubentries.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(includeSubentries);

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

    persistentSearch = new StringArgument('C', "persistentSearch", false, 1,
         "ps[:changetype[:changesonly[:entrychgcontrols]]]",
         INFO_LDAPSEARCH_ARG_DESCRIPTION_PERSISTENT_SEARCH.get());
    persistentSearch.addLongIdentifier("persistent-search", true);
    persistentSearch.setArgumentGroupName(
         INFO_LDAPSEARCH_ARG_GROUP_CONTROLS.get());
    parser.addArgument(persistentSearch);

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

    final LinkedHashSet<String>
         suppressOperationalAttributeUpdatesAllowedValues =
              new LinkedHashSet<String>(4);
    suppressOperationalAttributeUpdatesAllowedValues.add("last-access-time");
    suppressOperationalAttributeUpdatesAllowedValues.add("last-login-time");
    suppressOperationalAttributeUpdatesAllowedValues.add("last-login-ip");
    suppressOperationalAttributeUpdatesAllowedValues.add("lastmod");
    suppressOperationalAttributeUpdates = new StringArgument(null,
         "suppressOperationalAttributeUpdates", false, -1,
         INFO_PLACEHOLDER_ATTR.get(),
         INFO_LDAPSEARCH_ARG_DESCRIPTION_SUPPRESS_OP_ATTR_UPDATES.get(),
         suppressOperationalAttributeUpdatesAllowedValues);
    suppressOperationalAttributeUpdates.addLongIdentifier(
         "suppress-operational-attribute-updates", true);
    suppressOperationalAttributeUpdates.setArgumentGroupName(
         INFO_LDAPMODIFY_ARG_GROUP_CONTROLS.get());
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
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Control> getBindControls()
  {
    final ArrayList<Control> bindControls = new ArrayList<Control>(10);

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
      final ArrayList<SortKey> sortKeyList = new ArrayList<SortKey>(5);
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
    final ArrayList<EntryTransformation> transformations =
         new ArrayList<EntryTransformation>(5);
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
             outputFormatStr.equals("tab-delimited"))
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

      outputHandler = new ColumnFormatterLDAPSearchOutputHandler(this,
           (outputFormatStr.equals("csv")
                ? OutputFormat.CSV
                : OutputFormat.TAB_DELIMITED_TEXT),
           requestedAttributes, WRAP_COLUMN);
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
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();

    options.setUseSynchronousMode(true);
    options.setFollowReferrals(followReferrals.isPresent());
    options.setUnsolicitedNotificationHandler(this);

    return options;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // If we should use an output file, then set that up now.  Otherwise, write
    // the header to standard output.
    if (outputFile.isPresent())
    {
      if (! separateOutputFilePerSearch.isPresent())
      {
        try
        {
          final FileOutputStream fos =
               new FileOutputStream(outputFile.getValue());
          if (teeResultsToStandardOut.isPresent())
          {
            outStream = new PrintStream(new TeeOutputStream(fos, getOut()));
          }
          else
          {
            outStream = new PrintStream(fos);
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
      final ArrayList<String> attrList = new ArrayList<String>(10);
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
  private ResultCode searchWithLDAPURLs(final LDAPConnectionPool pool,
                                        final FixedRateBarrier rateLimiter,
                                        final List<Control> searchControls)
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
               url.getBaseDN().toString(), scope.getValue(), derefPolicy,
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
  private ResultCode searchWithFilterFile(final LDAPConnectionPool pool,
                                          final String[] attributes,
                                          final FixedRateBarrier rateLimiter,
                                          final List<Control> searchControls)
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
  private ResultCode searchWithFilter(final LDAPConnectionPool pool,
                                      final Filter filter,
                                      final String[] attributes,
                                      final FixedRateBarrier rateLimiter,
                                      final List<Control> searchControls)
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
  private ResultCode doSearch(final LDAPConnectionPool pool,
                              final SearchRequest searchRequest,
                              final FixedRateBarrier rateLimiter,
                              final List<Control> searchControls)
  {
    if (separateOutputFilePerSearch.isPresent())
    {
      try
      {
        final String path = outputFile.getValue().getAbsolutePath() + '.' +
             outputFileCounter.getAndIncrement();
        final FileOutputStream fos = new FileOutputStream(path);
        if (teeResultsToStandardOut.isPresent())
        {
          outStream = new PrintStream(new TeeOutputStream(fos, getOut()));
        }
        else
        {
          outStream = new PrintStream(fos);
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
   */
  private List<Control> getSearchControls()
  {
    final ArrayList<Control> controls = new ArrayList<Control>(10);

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

    if (accountUsable.isPresent())
    {
      controls.add(new AccountUsableRequestControl(true));
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

    if (includeSubentries.isPresent())
    {
      controls.add(new SubentriesRequestControl(true));
    }

    if (manageDsaIT.isPresent())
    {
      controls.add(new ManageDsaITRequestControl(true));
    }

    if (realAttributesOnly.isPresent())
    {
      controls.add(new RealAttributesOnlyRequestControl(true));
    }

    if (virtualAttributesOnly.isPresent())
    {
      controls.add(new VirtualAttributesOnlyRequestControl(true));
    }

    if (excludeBranch.isPresent())
    {
      final ArrayList<String> dns =
           new ArrayList<String>(excludeBranch.getValues().size());
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

    return controls;
  }



  /**
   * Displays information about the provided result, including special
   * processing for a number of supported response controls.
   *
   * @param  result  The result to examine.
   */
  void displayResult(final LDAPResult result)
  {
    outputHandler.formatResult(result);
  }



  /**
   * Writes the provided message to the output stream.
   *
   * @param  message  The message to be written.
   */
  void writeOut(final String message)
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
  void writeErr(final String message)
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
  private void commentToOut(final String message)
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
  private void commentToErr(final String message)
  {
    for (final String line : StaticUtils.wrapLine(message, (WRAP_COLUMN - 2)))
    {
      writeErr("# " + line);
    }
  }



  /**
   * Sets the output handler that should be used by this tool  This is primarily
   * intended for testing purposes.
   *
   * @param  outputHandler  The output handler that should be used by this tool.
   */
  void setOutputHandler(final LDAPSearchOutputHandler outputHandler)
  {
    this.outputHandler = outputHandler;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(final LDAPConnection connection,
                                            final ExtendedResult notification)
  {
    outputHandler.formatUnsolicitedNotification(connection, notification);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>(5);

    String[] args =
    {
      "--hostname", "directory.example.com",
      "--port", "389",
      "--bindDN", "uid=jdoe,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "ou=People,dc=example,dc=com",
      "--searchScope", "sub",
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
      "--searchScope", "sub",
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
      "--searchScope", "base",
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
      "--searchScope", "sub",
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
      "--searchScope", "sub",
      "(&(givenName=John)(sn=Doe))",
      "debugsearchindex"
    };
    examples.put(args, INFO_LDAPSEARCH_EXAMPLE_5.get());

    return examples;
  }
}
