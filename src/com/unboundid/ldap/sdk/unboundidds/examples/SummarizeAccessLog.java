/*
 * Copyright 2009-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2022 Ping Identity Corporation
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
 * Copyright (C) 2009-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;
import javax.crypto.BadPaddingException;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            AbandonRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AccessLogReader;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AddResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.BindResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.CompareResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.ConnectAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.DeleteResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.DisconnectAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            ExtendedRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            ExtendedResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            ModifyDNResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.ModifyResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            OperationRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            OperationResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.SearchRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.SearchResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            SecurityNegotiationAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.UnbindRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.json.JSONAccessLogReader;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.text.
            TextFormattedAccessLogReader;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OIDRegistry;
import com.unboundid.util.OIDRegistryItem;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ReverseComparator;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;



/**
 * This class provides a tool that may be used to read and summarize the
 * contents of one or more access log files from Ping Identity, UnboundID and
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
 * Information that will be reported includes:
 * <UL>
 *   <LI>The total length of time covered by the log files.</LI>
 *   <LI>The number of connections established and disconnected, the addresses
 *       of the most commonly-connecting clients, and the average rate of
 *       connects and disconnects per second.</LI>
 *   <LI>The number of operations processed, overall and by operation type,
 *       and the average rate of operations per second.</LI>
 *   <LI>The average duration for operations processed, overall and by operation
 *       type.</LI>
 *   <LI>A breakdown of operation processing times into a number of predefined
 *       categories, ranging from less than one millisecond to over one
 *       minute.</LI>
 *   <LI>A breakdown of the most common result codes for each type of operation
 *       and their relative frequencies.</LI>
 *   <LI>The most common types of extended requests processed and their
 *       relative frequencies.</LI>
 *   <LI>The number of unindexed search operations processed and the most common
 *       types of filters used in unindexed searches.</LI>
 *   <LI>A breakdown of the relative frequencies for each type of search
 *       scope.</LI>
 *   <LI>The most common types of search filters used for search
 *       operations and their relative frequencies.</LI>
 * </UL>
 * It is designed to work with access log files using either the default log
 * format with separate request and response messages, as well as log files
 * in which the request and response details have been combined on the same
 * line.  The log files to be processed should be provided as command-line
 * arguments.
 * <BR><BR>
 * The APIs demonstrated by this example include:
 * <UL>
 *   <LI>Access log parsing (from the
 *       {@code com.unboundid.ldap.sdk.unboundidds.logs} package)</LI>
 *   <LI>Argument parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SummarizeAccessLog
       extends CommandLineTool
       implements Serializable
{
  /**
   * The column at which long lines should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7189168366509887130L;



  // Variables used for accessing argument information.
  @Nullable private ArgumentParser argumentParser;

  // An argument that may be used to indicate that the summarized output should
  // not be anonymized, and should include attribute values.
  @Nullable private BooleanArgument doNotAnonymize;

  // An argument that may be used to indicate that the log files are compressed.
  @Nullable private BooleanArgument isCompressed;

  // An argument that may be used to indicate that the log content is
  // JSON-formatted rather than text-formatted.
  @Nullable private BooleanArgument json;

  // An argument used to specify the encryption passphrase.
  @Nullable private FileArgument encryptionPassphraseFile;

  // An argument used to specify the maximum number of values to report for each
  // item.
  @Nullable private IntegerArgument reportCount;

  // The decimal format that will be used for this class.
  @NotNull private final DecimalFormat decimalFormat;

  // The total duration for log content, in milliseconds.
  private long logDurationMillis;

  // The total processing time for each type of operation.
  private double addProcessingDuration;
  private double bindProcessingDuration;
  private double compareProcessingDuration;
  private double deleteProcessingDuration;
  private double extendedProcessingDuration;
  private double modifyProcessingDuration;
  private double modifyDNProcessingDuration;
  private double searchProcessingDuration;

  // A variable used for tracking total  work queue wait time.
  private long totalWorkQueueWaitTime;

  // A variable used for counting the number of messages of each type.
  private long numAbandons;
  private long numAdds;
  private long numBinds;
  private long numCompares;
  private long numConnects;
  private long numDeletes;
  private long numDisconnects;
  private long numExtended;
  private long numModifies;
  private long numModifyDNs;
  private long numSearches;
  private long numUnbinds;

  // The number of operations of each type that accessed uncached data.
  private long numUncachedAdds;
  private long numUncachedBinds;
  private long numUncachedCompares;
  private long numUncachedDeletes;
  private long numUncachedExtended;
  private long numUncachedModifies;
  private long numUncachedModifyDNs;
  private long numUncachedSearches;

  // The number of unindexed searches processed within the server.
  private long numUnindexedAttempts;
  private long numUnindexedFailed;
  private long numUnindexedSuccessful;

  // The number of request and response controls used.
  private long numRequestControls;
  private long numResponseControls;

  // Variables used for maintaining counts for common types of information.
  @NotNull private final HashMap<Long,AtomicLong> searchEntryCounts;
  @NotNull private final HashMap<Long,String> ipAddressesByConnectionID;
  @NotNull private final HashMap<ResultCode,AtomicLong> addResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> bindResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> compareResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> deleteResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> extendedResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> modifyResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> modifyDNResultCodes;
  @NotNull private final HashMap<ResultCode,AtomicLong> searchResultCodes;
  @NotNull private final HashMap<SearchScope,AtomicLong> searchScopes;
  @NotNull private final HashMap<String,AtomicLong> authenticationTypes;
  @NotNull private final HashMap<String,AtomicLong> authzDNs;
  @NotNull private final HashMap<String,AtomicLong> bindFailuresByDN;
  @NotNull private final HashMap<String,AtomicLong> bindFailuresByIPAddress;
  @NotNull private final HashMap<String,AtomicLong> consecutiveFailedBindsByDN;
  @NotNull private final HashMap<String,AtomicLong> outstandingFailedBindDNs;
  @NotNull private final HashMap<String,AtomicLong> successfulBindDNs;
  @NotNull private final HashMap<String,AtomicLong> clientAddresses;
  @NotNull private final HashMap<String,AtomicLong> clientConnectionPolicies;
  @NotNull private final HashMap<String,AtomicLong> disconnectReasons;
  @NotNull private final HashMap<String,AtomicLong> extendedOperations;
  @NotNull private final HashMap<String,AtomicLong> filterComponentCounts;
  @NotNull private final HashMap<String,AtomicLong> filterTypes;
  @NotNull private final HashMap<String,AtomicLong> mostExpensiveFilters;
  @NotNull private final HashMap<String,AtomicLong> multiEntryFilters;
  @NotNull private final HashMap<String,AtomicLong> noEntryFilters;
  @NotNull private final HashMap<String,AtomicLong> oneEntryFilters;
  @NotNull private final HashMap<String,AtomicLong> preAuthzPrivilegesUsed;
  @NotNull private final HashMap<String,AtomicLong> privilegesMissing;
  @NotNull private final HashMap<String,AtomicLong> privilegesUsed;
  @NotNull private final HashMap<String,AtomicLong> requestControlOIDs;
  @NotNull private final HashMap<String,AtomicLong> responseControlOIDs;
  @NotNull private final HashMap<String,AtomicLong> searchBaseDNs;
  @NotNull private final HashMap<String,AtomicLong> tlsCipherSuites;
  @NotNull private final HashMap<String,AtomicLong> tlsProtocols;
  @NotNull private final HashMap<String,AtomicLong> unindexedFilters;
  @NotNull private final HashMap<String,String> extendedOperationOIDsToNames;
  @NotNull private final HashSet<String> processedRequests;
  @NotNull private final LinkedHashMap<Long,AtomicLong> addProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> bindProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> compareProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> deleteProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> extendedProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> modifyProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> modifyDNProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> searchProcessingTimes;
  @NotNull private final LinkedHashMap<Long,AtomicLong> workQueueWaitTimes;
  @NotNull private final LinkedHashSet<Filter>
       filtersRepresentingPotentialInjectionAttempt;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String[] args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream)
  {
    final SummarizeAccessLog summarizer =
         new SummarizeAccessLog(outStream, errStream);
    return summarizer.runTool(args);
  }



  /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
  public SummarizeAccessLog(@Nullable final OutputStream outStream,
                            @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    argumentParser = null;
    doNotAnonymize = null;
    isCompressed = null;
    json = null;
    encryptionPassphraseFile = null;
    reportCount = null;

    decimalFormat = new DecimalFormat("0.000");

    logDurationMillis = 0L;

    addProcessingDuration = 0.0;
    bindProcessingDuration = 0.0;
    compareProcessingDuration = 0.0;
    deleteProcessingDuration = 0.0;
    extendedProcessingDuration = 0.0;
    modifyProcessingDuration = 0.0;
    modifyDNProcessingDuration = 0.0;
    searchProcessingDuration = 0.0;

    totalWorkQueueWaitTime = 0L;

    numAbandons = 0L;
    numAdds = 0L;
    numBinds = 0L;
    numCompares = 0L;
    numConnects = 0L;
    numDeletes = 0L;
    numDisconnects = 0L;
    numExtended = 0L;
    numModifies = 0L;
    numModifyDNs = 0L;
    numSearches = 0L;
    numUnbinds = 0L;

    numUncachedAdds = 0L;
    numUncachedBinds = 0L;
    numUncachedCompares = 0L;
    numUncachedDeletes = 0L;
    numUncachedExtended = 0L;
    numUncachedModifies = 0L;
    numUncachedModifyDNs = 0L;
    numUncachedSearches = 0L;

    numUnindexedAttempts = 0L;
    numUnindexedFailed = 0L;
    numUnindexedSuccessful = 0L;

    numRequestControls = 0L;
    numResponseControls = 0L;

    searchEntryCounts = new HashMap<>(StaticUtils.computeMapCapacity(10));
    ipAddressesByConnectionID =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    addResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    bindResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    compareResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    deleteResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    extendedResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    modifyResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    modifyDNResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    searchResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    searchScopes = new HashMap<>(StaticUtils.computeMapCapacity(4));
    authenticationTypes = new HashMap<>(StaticUtils.computeMapCapacity(100));
    authzDNs = new HashMap<>(StaticUtils.computeMapCapacity(100));
    bindFailuresByDN = new HashMap<>(StaticUtils.computeMapCapacity(100));
    bindFailuresByIPAddress =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    outstandingFailedBindDNs =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    successfulBindDNs = new HashMap<>(StaticUtils.computeMapCapacity(100));
    clientAddresses = new HashMap<>(StaticUtils.computeMapCapacity(100));
    clientConnectionPolicies =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    disconnectReasons = new HashMap<>(StaticUtils.computeMapCapacity(100));
    extendedOperations = new HashMap<>(StaticUtils.computeMapCapacity(10));
    filterComponentCounts = new HashMap<>(StaticUtils.computeMapCapacity(10));
    filterTypes = new HashMap<>(StaticUtils.computeMapCapacity(100));
    mostExpensiveFilters = new HashMap<>(StaticUtils.computeMapCapacity(100));
    multiEntryFilters = new HashMap<>(StaticUtils.computeMapCapacity(100));
    noEntryFilters = new HashMap<>(StaticUtils.computeMapCapacity(100));
    oneEntryFilters = new HashMap<>(StaticUtils.computeMapCapacity(100));
    preAuthzPrivilegesUsed = new HashMap<>(StaticUtils.computeMapCapacity(100));
    privilegesMissing = new HashMap<>(StaticUtils.computeMapCapacity(100));
    privilegesUsed = new HashMap<>(StaticUtils.computeMapCapacity(100));
    requestControlOIDs = new HashMap<>(StaticUtils.computeMapCapacity(100));
    responseControlOIDs = new HashMap<>(StaticUtils.computeMapCapacity(100));
    searchBaseDNs = new HashMap<>(StaticUtils.computeMapCapacity(100));
    tlsCipherSuites = new HashMap<>(StaticUtils.computeMapCapacity(100));
    tlsProtocols = new HashMap<>(StaticUtils.computeMapCapacity(100));
    unindexedFilters = new HashMap<>(StaticUtils.computeMapCapacity(100));
    consecutiveFailedBindsByDN =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    extendedOperationOIDsToNames =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    processedRequests = new HashSet<>(StaticUtils.computeMapCapacity(100));
    addProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    bindProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    compareProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    deleteProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    extendedProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    modifyProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    modifyDNProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    searchProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    workQueueWaitTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    filtersRepresentingPotentialInjectionAttempt =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));

    populateProcessingTimeMap(addProcessingTimes);
    populateProcessingTimeMap(bindProcessingTimes);
    populateProcessingTimeMap(compareProcessingTimes);
    populateProcessingTimeMap(deleteProcessingTimes);
    populateProcessingTimeMap(extendedProcessingTimes);
    populateProcessingTimeMap(modifyProcessingTimes);
    populateProcessingTimeMap(modifyDNProcessingTimes);
    populateProcessingTimeMap(searchProcessingTimes);
    populateProcessingTimeMap(workQueueWaitTimes);
  }



  /**
   * Retrieves the name for this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "summarize-access-log";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "Examine one or more access log files from Ping Identity, " +
         "UnboundID, or Nokia/Alcatel-Lucent 8661 server products to display " +
         "a number of metrics about operations processed within the server.";
  }



  /**
   * Retrieves the version string for this tool.
   *
   * @return  The version string for this tool.
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Retrieves the minimum number of unnamed trailing arguments that are
   * required.
   *
   * @return  One, to indicate that at least one trailing argument (representing
   *          the path to an access log file) must be provided.
   */
  @Override()
  public int getMinTrailingArguments()
  {
    return 1;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that may be
   * provided for this tool.
   *
   * @return  The maximum number of unnamed trailing arguments that may be
   *          provided for this tool.
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return -1;
  }



  /**
   * Retrieves a placeholder string that should be used for trailing arguments
   * in the usage information for this tool.
   *
   * @return  A placeholder string that should be used for trailing arguments in
   *          the usage information for this tool.
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return "{path}";
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Adds the command-line arguments supported for use with this tool to the
   * provided argument parser.  The tool may need to retain references to the
   * arguments (and/or the argument parser, if trailing arguments are allowed)
   * to it in order to obtain their values for use in later processing.
   *
   * @param  parser  The argument parser to which the arguments are to be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding any of the
   *                             tool-specific arguments to the provided
   *                             argument parser.
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    // We need to save a reference to the argument parser so that we can get
    // the trailing arguments later.
    argumentParser = parser;

    // Add an argument that makes it possible to read a JSON-formatted access
    // log file.
    String description = "Indicates that the log file contains " +
         "JSON-formatted log messages rather than text-formatted messages.";
    json = new BooleanArgument(null, "json", description);
    parser.addArgument(json);


    // Add an argument that makes it possible to read a compressed log file.
    // Note that this argument is no longer needed for dealing with compressed
    // files, since the tool will automatically detect whether a file is
    // compressed.  However, the argument is still provided for the purpose of
    // backward compatibility.
    description = "Indicates that the log file is compressed.";
    isCompressed = new BooleanArgument('c', "isCompressed", description);
    isCompressed.addLongIdentifier("is-compressed", true);
    isCompressed.addLongIdentifier("compressed", true);
    isCompressed.setHidden(true);
    parser.addArgument(isCompressed);


    // Add an argument that indicates that the tool should read the encryption
    // passphrase from a file.
    description = "Indicates that the log file is encrypted and that the " +
         "encryption passphrase is contained in the specified file.  If " +
         "the log data is encrypted and this argument is not provided, then " +
         "the tool will interactively prompt for the encryption passphrase.";
    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null, description, true, true,
         true, false);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    parser.addArgument(encryptionPassphraseFile);


    // Add an argument that indicates the number of values to display for each
    // item being summarized.
    description = "The number of values to display for each item being " +
         "summarized.  A value of zero indicates that all items should be " +
         "displayed.  If this is not provided, a default value of 20 will " +
         "be used.";
    reportCount = new IntegerArgument(null, "reportCount", false, 0, null,
         description, 0, Integer.MAX_VALUE, 20);
    reportCount.addLongIdentifier("report-count", true);
    reportCount.addLongIdentifier("maximumCount", true);
    reportCount.addLongIdentifier("maximum-count", true);
    reportCount.addLongIdentifier("maxCount", true);
    reportCount.addLongIdentifier("max-count", true);
    reportCount.addLongIdentifier("count", true);
    parser.addArgument(reportCount);


    // Add an argument that indicates that the output should not be anonymized.
    description = "Do not anonymize the output, but include actual attribute " +
         "values in filters and DNs.  This will also have the effect of " +
         "de-generifying those values, so output including the most common " +
         "filters and DNs in some category will be specific instances of " +
         "those filters and DNs instead of generic patterns.";
    doNotAnonymize = new BooleanArgument(null, "doNotAnonymize", 1,
         description);
    doNotAnonymize.addLongIdentifier("do-not-anonymize", true);
    doNotAnonymize.addLongIdentifier("deAnonymize", true);
    doNotAnonymize.addLongIdentifier("de-anonymize", true);
    parser.addArgument(doNotAnonymize);
  }



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and immediately
   * before the {@link #doToolProcessing} method is invoked.
   *
   * @throws  ArgumentException  If there was a problem with the command-line
   *                             arguments provided to this program.
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // Make sure that at least one access log file path was provided.
    final List<String> trailingArguments =
         argumentParser.getTrailingArguments();
    if ((trailingArguments == null) || trailingArguments.isEmpty())
    {
      throw new ArgumentException("No access log file paths were provided.");
    }
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    int displayCount = reportCount.getValue();
    if (displayCount <= 0)
    {
      displayCount = Integer.MAX_VALUE;
    }

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
        Debug.debugException(e);
        err(e.getMessage());
        return e.getResultCode();
      }
    }


    long logLines = 0L;
    for (final String path : argumentParser.getTrailingArguments())
    {
      final File f = new File(path);
      out("Examining access log ", f.getAbsolutePath());
      AccessLogReader reader = null;
      InputStream inputStream = null;
      try
      {
        inputStream = new FileInputStream(f);

        final ObjectPair<InputStream,String> p =
             ToolUtils.getPossiblyPassphraseEncryptedInputStream(inputStream,
                  encryptionPassphrase,
                  (! encryptionPassphraseFile.isPresent()),
                  "Log file '" + path + "' is encrypted.  Please enter the " +
                       "encryption passphrase:",
                  "ERROR:  The provided passphrase was incorrect.",
                  getOut(), getErr());
        inputStream = p.getFirst();
        if ((p.getSecond() != null) && (encryptionPassphrase == null))
        {
          encryptionPassphrase = p.getSecond();
        }

        if (isCompressed.isPresent())
        {
          inputStream = new GZIPInputStream(inputStream);
        }
        else
        {
          inputStream =
               ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);
        }

        if (json.isPresent())
        {
          reader = new JSONAccessLogReader(inputStream);
        }
        else
        {
          reader = new TextFormattedAccessLogReader(inputStream);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err("Unable to open access log file ", f.getAbsolutePath(), ":  ",
            StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
      finally
      {
        if ((reader == null) && (inputStream != null))
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

      long startTime = 0L;
      long stopTime  = 0L;

      while (true)
      {
        final AccessLogMessage msg;
        try
        {
          msg = reader.readMessage();
        }
        catch (final IOException ioe)
        {
          Debug.debugException(ioe);
          err("Error reading from access log file ", f.getAbsolutePath(),
              ":  ", StaticUtils.getExceptionMessage(ioe));

          if ((ioe.getCause() != null) &&
               (ioe.getCause() instanceof BadPaddingException))
          {
            err("This error is likely because the log is encrypted and the " +
                 "server still has the log file open.  It is recommended " +
                 "that you only try to examine encrypted logs after they " +
                 "have been rotated.  You can use the rotate-log tool to " +
                 "force a rotation at any time.  Attempting to proceed with " +
                 "just the data that was successfully read.");
            break;
          }
          else
          {
            return ResultCode.LOCAL_ERROR;
          }
        }
        catch (final LogException le)
        {
          Debug.debugException(le);
          err("Encountered an error while attempting to parse a line in" +
              "access log file ", f.getAbsolutePath(), ":  ",
              StaticUtils.getExceptionMessage(le));
          continue;
        }

        if (msg == null)
        {
          break;
        }

        logLines++;
        stopTime = msg.getTimestamp().getTime();
        if (startTime == 0L)
        {
          startTime = stopTime;
        }

        switch (msg.getMessageType())
        {
          case CONNECT:
            processConnect((ConnectAccessLogMessage) msg);
            break;
          case SECURITY_NEGOTIATION:
            processSecurityNegotiation(
                 (SecurityNegotiationAccessLogMessage) msg);
            break;
          case DISCONNECT:
            processDisconnect((DisconnectAccessLogMessage) msg);
            break;
          case REQUEST:
            switch (((OperationRequestAccessLogMessage) msg).getOperationType())
            {
              case ABANDON:
                processAbandonRequest((AbandonRequestAccessLogMessage) msg);
                break;
              case EXTENDED:
                processExtendedRequest((ExtendedRequestAccessLogMessage) msg);
                break;
              case SEARCH:
                processSearchRequest((SearchRequestAccessLogMessage) msg);
                break;
              case UNBIND:
                processUnbindRequest((UnbindRequestAccessLogMessage) msg);
                break;
            }
            break;
          case RESULT:
            switch (((OperationRequestAccessLogMessage) msg).getOperationType())
            {
              case ADD:
                processAddResult((AddResultAccessLogMessage) msg);
                break;
              case BIND:
                processBindResult((BindResultAccessLogMessage) msg);
                break;
              case COMPARE:
                processCompareResult((CompareResultAccessLogMessage) msg);
                break;
              case DELETE:
                processDeleteResult((DeleteResultAccessLogMessage) msg);
                break;
              case EXTENDED:
                processExtendedResult((ExtendedResultAccessLogMessage) msg);
                break;
              case MODIFY:
                processModifyResult((ModifyResultAccessLogMessage) msg);
                break;
              case MODDN:
                processModifyDNResult((ModifyDNResultAccessLogMessage) msg);
                break;
              case SEARCH:
                processSearchResult((SearchResultAccessLogMessage) msg);
                break;
            }
            break;

          case ASSURANCE_COMPLETE:
          case CLIENT_CERTIFICATE:
          case ENTRY_REBALANCING_REQUEST:
          case ENTRY_REBALANCING_RESULT:
          case FORWARD:
          case FORWARD_FAILED:
          case ENTRY:
          case REFERENCE:
          default:
            // Nothing needs to be done for these message types.
        }
      }

      try
      {
        reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      logDurationMillis += (stopTime - startTime);


      // If there are any outstanding authentication failures, then update the
      // set of consecutive failures as appropriate.
      for (final Map.Entry<String,AtomicLong> e :
           outstandingFailedBindDNs.entrySet())
      {
        final String dn = e.getKey();
        final AtomicLong outstandingFailureCount = e.getValue();
        final AtomicLong consecutiveFailures =
             consecutiveFailedBindsByDN.get(dn);
        if ((consecutiveFailures == null) ||
           (outstandingFailureCount.get() > consecutiveFailures.get()))
        {
          consecutiveFailedBindsByDN.put(dn, outstandingFailureCount);
        }
      }
      outstandingFailedBindDNs.clear();
    }


    final int numFiles = argumentParser.getTrailingArguments().size();
    out();
    out("Examined ", logLines, " lines in ", numFiles,
        ((numFiles == 1) ? " file" : " files"),
        " covering a total duration of ",
        StaticUtils.millisToHumanReadableDuration(logDurationMillis));
    if (logLines == 0)
    {
      return ResultCode.SUCCESS;
    }

    out();

    final double logDurationSeconds   = logDurationMillis / 1_000.0;
    final double connectsPerSecond    = numConnects / logDurationSeconds;
    final double disconnectsPerSecond = numDisconnects / logDurationSeconds;

    out("Total connections established:  ", numConnects, " (",
        decimalFormat.format(connectsPerSecond), "/second)");
    out("Total disconnects:  ", numDisconnects, " (",
        decimalFormat.format(disconnectsPerSecond), "/second)");

    printCounts(clientAddresses, "Most common client addresses:", "address",
         "addresses");

    printCounts(clientConnectionPolicies,
         "Most common client connection policies:", "policy", "policies");

    printCounts(tlsProtocols, "Most common TLS protocol versions:", "version",
         "versions");

    printCounts(tlsCipherSuites, "Most common TLS cipher suites:",
         "cipher suite", "cipher suites");

    printCounts(disconnectReasons, "Most common disconnect reasons:", "reason",
         "reasons");

    final long totalOps = numAbandons + numAdds + numBinds + numCompares +
         numDeletes + numExtended + numModifies + numModifyDNs + numSearches +
         numUnbinds;
    final long totalResults = totalOps - numAbandons - numUnbinds;

    if (totalOps > 0)
    {
      final double percentAbandon  = 100.0 * numAbandons / totalOps;
      final double percentAdd      = 100.0 * numAdds / totalOps;
      final double percentBind     = 100.0 * numBinds / totalOps;
      final double percentCompare  = 100.0 * numCompares / totalOps;
      final double percentDelete   = 100.0 * numDeletes / totalOps;
      final double percentExtended = 100.0 * numExtended / totalOps;
      final double percentModify   = 100.0 * numModifies / totalOps;
      final double percentModifyDN = 100.0 * numModifyDNs / totalOps;
      final double percentSearch   = 100.0 * numSearches / totalOps;
      final double percentUnbind   = 100.0 * numUnbinds / totalOps;

      final double abandonsPerSecond  = numAbandons / logDurationSeconds;
      final double addsPerSecond      = numAdds / logDurationSeconds;
      final double bindsPerSecond     = numBinds / logDurationSeconds;
      final double comparesPerSecond  = numCompares / logDurationSeconds;
      final double deletesPerSecond   = numDeletes / logDurationSeconds;
      final double extendedPerSecond  = numExtended / logDurationSeconds;
      final double modifiesPerSecond  = numModifies / logDurationSeconds;
      final double modifyDNsPerSecond = numModifyDNs / logDurationSeconds;
      final double searchesPerSecond  = numSearches / logDurationSeconds;
      final double unbindsPerSecond   = numUnbinds / logDurationSeconds;

      out();
      out("Total operations examined:  ", totalOps);
      out("Abandon operations examined:  ", numAbandons, " (",
          decimalFormat.format(percentAbandon), "%, ",
          decimalFormat.format(abandonsPerSecond), "/second)");
      out("Add operations examined:  ", numAdds, " (",
          decimalFormat.format(percentAdd), "%, ",
          decimalFormat.format(addsPerSecond), "/second)");
      out("Bind operations examined:  ", numBinds, " (",
          decimalFormat.format(percentBind), "%, ",
          decimalFormat.format(bindsPerSecond), "/second)");
      out("Compare operations examined:  ", numCompares, " (",
          decimalFormat.format(percentCompare), "%, ",
          decimalFormat.format(comparesPerSecond), "/second)");
      out("Delete operations examined:  ", numDeletes, " (",
          decimalFormat.format(percentDelete), "%, ",
          decimalFormat.format(deletesPerSecond), "/second)");
      out("Extended operations examined:  ", numExtended, " (",
          decimalFormat.format(percentExtended), "%, ",
          decimalFormat.format(extendedPerSecond), "/second)");
      out("Modify operations examined:  ", numModifies, " (",
          decimalFormat.format(percentModify), "%, ",
          decimalFormat.format(modifiesPerSecond), "/second)");
      out("Modify DN operations examined:  ", numModifyDNs, " (",
          decimalFormat.format(percentModifyDN), "%, ",
          decimalFormat.format(modifyDNsPerSecond), "/second)");
      out("Search operations examined:  ", numSearches, " (",
          decimalFormat.format(percentSearch), "%, ",
          decimalFormat.format(searchesPerSecond), "/second)");
      out("Unbind operations examined:  ", numUnbinds, " (",
          decimalFormat.format(percentUnbind), "%, ",
          decimalFormat.format(unbindsPerSecond), "/second)");

      final double totalProcessingDuration = addProcessingDuration +
           bindProcessingDuration + compareProcessingDuration +
           deleteProcessingDuration + extendedProcessingDuration +
           modifyProcessingDuration + modifyDNProcessingDuration +
           searchProcessingDuration;

      out();
      out("Average operation processing duration:  ",
          decimalFormat.format(totalProcessingDuration / totalOps), "ms");

      if (numAdds > 0)
      {
        out("Average add operation processing duration:  ",
            decimalFormat.format(addProcessingDuration / numAdds), "ms");
      }

      if (numBinds > 0)
      {
        out("Average bind operation processing duration:  ",
            decimalFormat.format(bindProcessingDuration / numBinds), "ms");
      }

      if (numCompares > 0)
      {
        out("Average compare operation processing duration:  ",
            decimalFormat.format(compareProcessingDuration / numCompares),
            "ms");
      }

      if (numDeletes > 0)
      {
        out("Average delete operation processing duration:  ",
            decimalFormat.format(deleteProcessingDuration / numDeletes), "ms");
      }

      if (numExtended > 0)
      {
        out("Average extended operation processing duration:  ",
            decimalFormat.format(extendedProcessingDuration / numExtended),
            "ms");
      }

      if (numModifies > 0)
      {
        out("Average modify operation processing duration:  ",
            decimalFormat.format(modifyProcessingDuration / numModifies), "ms");
      }

      if (numModifyDNs > 0)
      {
        out("Average modify DN operation processing duration:  ",
            decimalFormat.format(modifyDNProcessingDuration / numModifyDNs),
            "ms");
      }

      if (numSearches > 0)
      {
        out("Average search operation processing duration:  ",
            decimalFormat.format(searchProcessingDuration / numSearches), "ms");
      }

      printProcessingTimeHistogram("add", numAdds, addProcessingTimes);
      printProcessingTimeHistogram("bind", numBinds, bindProcessingTimes);
      printProcessingTimeHistogram("compare", numCompares,
                                   compareProcessingTimes);
      printProcessingTimeHistogram("delete", numDeletes, deleteProcessingTimes);
      printProcessingTimeHistogram("extended", numExtended,
                                   extendedProcessingTimes);
      printProcessingTimeHistogram("modify", numModifies,
                                   modifyProcessingTimes);
      printProcessingTimeHistogram("modify DN", numModifyDNs,
                                 modifyDNProcessingTimes);
      printProcessingTimeHistogram("search", numSearches,
                                   searchProcessingTimes);

      if (totalWorkQueueWaitTime > 0L)
      {
        out();
        out("Average work queue wait time:  ",
             decimalFormat.format(totalWorkQueueWaitTime / totalResults), "ms");
        printHistogram("Count of operations by work queue wait time:",
             totalResults, workQueueWaitTimes);
      }

      printResultCodeCounts(addResultCodes, "add");
      printResultCodeCounts(bindResultCodes, "bind");
      printResultCodeCounts(compareResultCodes, "compare");
      printResultCodeCounts(deleteResultCodes, "delete");
      printResultCodeCounts(extendedResultCodes, "extended");
      printResultCodeCounts(modifyResultCodes, "modify");
      printResultCodeCounts(modifyDNResultCodes, "modify DN");
      printResultCodeCounts(searchResultCodes, "search");

      printCounts(preAuthzPrivilegesUsed,
           "Most common pre-authorization privileges used:", "privilege",
           "privileges");
      printCounts(privilegesUsed, "Most common privileges used:", "privilege",
           "privileges");
      printCounts(privilegesMissing, "Most common missing privileges:",
           "privilege", "privileges");

      printCounts(successfulBindDNs,
           "Most common bind DNs used in successful authentication attempts:",
           "DN", "DNs");
      printCounts(bindFailuresByDN,
           "Most common bind DNs used in failed authentication attempts:",
           "DN", "DNs");
      printCounts(bindFailuresByIPAddress,
           "Most common IP addresses used in failed authentication attempts:",
           "IP", "IPs");
      if (doNotAnonymize.isPresent())
      {
        printCounts(consecutiveFailedBindsByDN,
             "Bind DNs with the most consecutive authentication failures:",
             "DN", "DNs");
      }
      printCounts(authenticationTypes, "Most common authentication types:",
           "authentication type", "authentication types");

      long numResultsWithAuthzID = 0L;
      for (final AtomicLong l : authzDNs.values())
      {
        numResultsWithAuthzID += l.get();
      }

      out();
      final double percentWithAuthzID =
           100.0 * numResultsWithAuthzID / totalOps;
      out("Number of operations with an alternate authorization identity:  ",
           numResultsWithAuthzID, " (",
           decimalFormat.format(percentWithAuthzID), "%)");

      printCounts(authzDNs, "Most common alternate authorization identity DNs:",
           "DN", "DNs");

      if (! requestControlOIDs.isEmpty())
      {
        final List<ObjectPair<String,Long>> controlCounts = new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(requestControlOIDs, controlCounts, displayCount,
             skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Most common request control types:");

        long count = -1L;
        for (final ObjectPair<String,Long> p : controlCounts)
        {
          count = p.getSecond();
          final double percent = 100.0 * count / numRequestControls;

          final String oid = p.getFirst();
          final OIDRegistryItem item = OIDRegistry.getDefault().get(oid);
          if (item == null)
          {
            out(p.getFirst(), ":  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
          else
          {
            out(p.getFirst(), " (", item.getName(), "):  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() + " additional " +
               getSingularOrPlural(skippedWithSameCount.get(), "control",
                    "controls") +
               " with a count of " + count + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() + " additional " +
               getSingularOrPlural(skippedWithLowerCount.get(), "control",
                    "controls") +
               " with a count that is less than " + count + " }");
        }
      }

      if (! responseControlOIDs.isEmpty())
      {
        final List<ObjectPair<String,Long>> controlCounts = new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(responseControlOIDs, controlCounts, displayCount,
             skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Most common response control types:");

        long count = -1L;
        for (final ObjectPair<String,Long> p : controlCounts)
        {
          count = p.getSecond();
          final double percent = 100.0 * count / numResponseControls;

          final String oid = p.getFirst();
          final OIDRegistryItem item = OIDRegistry.getDefault().get(oid);
          if (item == null)
          {
            out(p.getFirst(), ":  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
          else
          {
            out(p.getFirst(), " (", item.getName(), "):  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() + " additional " +
               getSingularOrPlural(skippedWithSameCount.get(), "control",
                    "controls") +
               " with a count of " + count + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() + " additional " +
               getSingularOrPlural(skippedWithLowerCount.get(), "control",
                    "controls") +
               " with a count that is less than " + count + " }");
        }
      }

      if (! extendedOperations.isEmpty())
      {
        final List<ObjectPair<String,Long>> extOpCounts = new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(extendedOperations, extOpCounts, displayCount,
             skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Most common extended operation types:");

        long count = -1L;
        for (final ObjectPair<String,Long> p : extOpCounts)
        {
          count = p.getSecond();
          final double percent = 100.0 * count / numExtended;

          final String oid = p.getFirst();
          final String name = extendedOperationOIDsToNames.get(oid);
          if (name == null)
          {
            out(p.getFirst(), ":  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
          else
          {
            out(p.getFirst(), " (", name, "):  ", p.getSecond(), " (",
                 decimalFormat.format(percent), "%)");
          }
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() +
               " additional extended " +
               getSingularOrPlural(skippedWithSameCount.get(), "operation",
                    "operations") +
               " with a count of " + count + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() +
               " additional extended " +
               getSingularOrPlural(skippedWithLowerCount.get(), "operation",
                    "operations") +
               " with a count that is less than " + count + " }");
        }
      }

      out();
      out("Number of unindexed search attempts:  ", numUnindexedAttempts);
      out("Number of successfully-completed unindexed searches:  ",
           numUnindexedSuccessful);
      out("Number of failed unindexed searches:  ", numUnindexedFailed);

      printCounts(unindexedFilters, "Most common unindexed search filters:",
           "filter", "filters");

      if (! searchScopes.isEmpty())
      {
        final List<ObjectPair<SearchScope,Long>> scopeCounts =
             new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(searchScopes, scopeCounts, displayCount,
             skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Most common search scopes:");

        long count = -1L;
        for (final ObjectPair<SearchScope,Long> p : scopeCounts)
        {
          count = p.getSecond();
          final double percent = 100.0 * count / numSearches;
          out(p.getFirst().getName().toLowerCase(), " (",
               p.getFirst().intValue(), "):  ", p.getSecond(), " (",
               decimalFormat.format(percent), "%)");
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() + " additional " +
               getSingularOrPlural(skippedWithSameCount.get(), "scope",
                    "scopes") +
               " with a count of " + count + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() + " additional " +
               getSingularOrPlural(skippedWithLowerCount.get(), "scope",
                    "scopes") +
               " with a count that is less than " + count + " }");
        }
      }

      if (! searchEntryCounts.isEmpty())
      {
        final List<ObjectPair<Long,Long>> entryCounts = new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(searchEntryCounts, entryCounts, displayCount,
             skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Most common search entry counts:");

        long count = -1L;
        for (final ObjectPair<Long,Long> p : entryCounts)
        {
          count = p.getSecond();
          final double percent = 100.0 * count / numSearches;
          out(p.getFirst(), " matching ",
               getSingularOrPlural(p.getFirst(), "entry", "entries"),
               ":  ", p.getSecond(), " (", decimalFormat.format(percent), "%)");
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() + " additional entry " +
               getSingularOrPlural(skippedWithSameCount.get(), "count",
                    "counts") +
               " with a count of " + count + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() +
               " additional entry " +
               getSingularOrPlural(skippedWithLowerCount.get(), "count",
                    "counts") +
               " with a count that is less than " + count + " }");
        }
      }

      printCounts(searchBaseDNs,
           "Most common base DNs for searches with a non-base scope:",
           "base DN", "base DNs");

      printCounts(filterTypes,
           "Most common filters for searches with a non-base scope:",
           "filter", "filters");

      printCounts(filterComponentCounts,
           "Most common search filter component counts:", "filter",
           "filters");

      if (doNotAnonymize.isPresent() &&
           (! filtersRepresentingPotentialInjectionAttempt.isEmpty()))
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             "Search filters that may indicate an unsuccessful injection " +
                  "attempt.  These include filters with an assertion value " +
                  "that contains one or more of the following:  parentheses, " +
                  "ampersands, pipes, single quotes, double quotes, or the " +
                  "words 'select' and 'from':");
        for (final Filter f : filtersRepresentingPotentialInjectionAttempt)
        {
          out("* " + f.toString());
        }
      }

      if (numSearches > 0L)
      {
        long numSearchesMatchingNoEntries = 0L;
        for (final AtomicLong l : noEntryFilters.values())
        {
          numSearchesMatchingNoEntries += l.get();
        }

        out();
        final double noEntryPercent =
             100.0 * numSearchesMatchingNoEntries / numSearches;
        out("Number of searches matching no entries:  ",
             numSearchesMatchingNoEntries, " (",
             decimalFormat.format(noEntryPercent), "%)");

        printCounts(noEntryFilters,
             "Most common filters for searches matching no entries:",
             "filter", "filters");


        long numSearchesMatchingOneEntry = 0L;
        for (final AtomicLong l : oneEntryFilters.values())
        {
          numSearchesMatchingOneEntry += l.get();
        }

        out();
        final double oneEntryPercent =
             100.0 * numSearchesMatchingOneEntry / numSearches;
        out("Number of searches matching one entry:  ",
             numSearchesMatchingOneEntry, " (",
             decimalFormat.format(oneEntryPercent), "%)");

        printCounts(oneEntryFilters,
             "Most common filters for searches matching one entry:",
             "filter", "filters");


        long numSearchesMatchingMultipleEntries = 0L;
        for (final AtomicLong l : multiEntryFilters.values())
        {
          numSearchesMatchingMultipleEntries += l.get();
        }

        out();
        final double multiEntryPercent =
             100.0 * numSearchesMatchingMultipleEntries / numSearches;
        out("Number of searches matching multiple entries:  ",
             numSearchesMatchingMultipleEntries, " (",
             decimalFormat.format(multiEntryPercent), "%)");

        printCounts(multiEntryFilters,
             "Most common filters for searches matching multiple entries:",
             "filter", "filters");
      }
    }

    if (! mostExpensiveFilters.isEmpty())
    {
        final List<ObjectPair<String,Long>> filterDurations = new ArrayList<>();
        final AtomicLong skippedWithSameCount = new AtomicLong(0L);
        final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
        getMostCommonElements(mostExpensiveFilters, filterDurations,
             displayCount, skippedWithSameCount, skippedWithLowerCount);

        out();
        out("Filters for searches with the longest processing times:");

        String durationStr = "";
        for (final ObjectPair<String,Long> p : filterDurations)
        {
          final long durationMicros = p.getSecond();
          final double durationMillis = durationMicros / 1_000.0;
          durationStr = decimalFormat.format(durationMillis) + " ms";
          out(p.getFirst(), ":  ", durationStr);
        }

        if (skippedWithSameCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithSameCount.get() + " additional " +
               getSingularOrPlural(skippedWithSameCount.get(), "filter",
                    "filters") +
               " with a duration of " + durationStr + " }");
        }

        if (skippedWithLowerCount.get() > 0L)
        {
          out("{ Skipped " + skippedWithLowerCount.get() + " additional " +
               getSingularOrPlural(skippedWithLowerCount.get(), "filter",
                    "filters") +
               " with a duration that is less than " + durationStr + " }");
        }
    }

    final long totalUncached = numUncachedAdds + numUncachedBinds +
         numUncachedCompares + numUncachedDeletes + numUncachedExtended +
         numUncachedModifies + numUncachedModifyDNs + numUncachedSearches;
    if (totalUncached > 0L)
    {
      out();
      out("Operations accessing uncached data:");
      printUncached("Add", numUncachedAdds, numAdds);
      printUncached("Bind", numUncachedBinds, numBinds);
      printUncached("Compare", numUncachedCompares, numCompares);
      printUncached("Delete", numUncachedDeletes, numDeletes);
      printUncached("Extended", numUncachedExtended, numExtended);
      printUncached("Modify", numUncachedModifies, numModifies);
      printUncached("Modify DN", numUncachedModifyDNs, numModifyDNs);
      printUncached("Search", numUncachedSearches, numSearches);
    }


    return ResultCode.SUCCESS;
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "/ds/logs/access"
    };
    final String description =
         "Analyze the contents of the /ds/logs/access access log file.";
    examples.put(args, description);

    return examples;
  }



  /**
   * Populates the provided processing time map with an initial set of values.
   *
   * @param  m  The processing time map to be populated.
   */
  private static void populateProcessingTimeMap(
                           @NotNull final HashMap<Long,AtomicLong> m)
  {
    m.put(1L, new AtomicLong(0L));
    m.put(2L, new AtomicLong(0L));
    m.put(3L, new AtomicLong(0L));
    m.put(5L, new AtomicLong(0L));
    m.put(10L, new AtomicLong(0L));
    m.put(20L, new AtomicLong(0L));
    m.put(30L, new AtomicLong(0L));
    m.put(50L, new AtomicLong(0L));
    m.put(100L, new AtomicLong(0L));
    m.put(1_000L, new AtomicLong(0L));
    m.put(2_000L, new AtomicLong(0L));
    m.put(3_000L, new AtomicLong(0L));
    m.put(5_000L, new AtomicLong(0L));
    m.put(10_000L, new AtomicLong(0L));
    m.put(20_000L, new AtomicLong(0L));
    m.put(30_000L, new AtomicLong(0L));
    m.put(60_000L, new AtomicLong(0L));
    m.put(Long.MAX_VALUE, new AtomicLong(0L));
  }



  /**
   * Performs any necessary processing for a connect message.
   *
   * @param  m  The log message to be processed.
   */
  private void processConnect(@NotNull final ConnectAccessLogMessage m)
  {
    numConnects++;

    final String clientAddr = m.getSourceAddress();
    if (clientAddr != null)
    {
      final Long connectionID = m.getConnectionID();
      if (connectionID != null)
      {
        ipAddressesByConnectionID.put(connectionID, clientAddr);
      }

      AtomicLong count = clientAddresses.get(clientAddr);
      if (count == null)
      {
        count = new AtomicLong(0L);
        clientAddresses.put(clientAddr, count);
      }
      count.incrementAndGet();
    }

    final String ccp = m.getClientConnectionPolicy();
    if (ccp != null)
    {
      AtomicLong l = clientConnectionPolicies.get(ccp);
      if (l == null)
      {
        l = new AtomicLong(0L);
        clientConnectionPolicies.put(ccp, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for a security negotiation message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSecurityNegotiation(
                    @NotNull final SecurityNegotiationAccessLogMessage m)
  {
    final String protocol = m.getProtocol();
    if (protocol != null)
    {
      AtomicLong l = tlsProtocols.get(protocol);
      if (l == null)
      {
        l = new AtomicLong(0L);
        tlsProtocols.put(protocol, l);
      }
      l.incrementAndGet();
    }

    final String cipherSuite = m.getCipher();
    if (cipherSuite != null)
    {
      AtomicLong l = tlsCipherSuites.get(cipherSuite);
      if (l == null)
      {
        l = new AtomicLong(0L);
        tlsCipherSuites.put(cipherSuite, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for a disconnect message.
   *
   * @param  m  The log message to be processed.
   */
  private void processDisconnect(@NotNull final DisconnectAccessLogMessage m)
  {
    numDisconnects++;

    final Long connectionID = m.getConnectionID();
    if (connectionID != null)
    {
      ipAddressesByConnectionID.remove(connectionID);
    }

    final String reason = m.getDisconnectReason();
    if (reason != null)
    {
      AtomicLong l = disconnectReasons.get(reason);
      if (l == null)
      {
        l = new AtomicLong(0L);
        disconnectReasons.put(reason, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for an abandon request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processAbandonRequest(
                    @NotNull final AbandonRequestAccessLogMessage m)
  {
    numAbandons++;
  }



  /**
   * Performs any necessary processing for an extended request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedRequest(
                    @NotNull final ExtendedRequestAccessLogMessage m)
  {
    processedRequests.add(m.getConnectionID() + "-" + m.getOperationID());
    processExtendedRequestInternal(m);
  }



  /**
   * Performs the internal processing for an extended request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedRequestInternal(
                    @NotNull final ExtendedRequestAccessLogMessage m)
  {
    final String oid = m.getRequestOID();
    if (oid != null)
    {
      AtomicLong l = extendedOperations.get(oid);
      if (l == null)
      {
        l  = new AtomicLong(0L);
        extendedOperations.put(oid, l);
      }
      l.incrementAndGet();

      final String requestType = m.getRequestType();
      if ((requestType != null) &&
           (! extendedOperationOIDsToNames.containsKey(oid)))
      {
        extendedOperationOIDsToNames.put(oid, requestType);
      }
    }
  }



  /**
   * Performs any necessary processing for a search request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchRequest(
                    @NotNull final SearchRequestAccessLogMessage m)
  {
    processedRequests.add(m.getConnectionID() + "-" + m.getOperationID());
    processSearchRequestInternal(m);
  }



  /**
   * Performs any necessary processing for a search request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchRequestInternal(
                    @NotNull final SearchRequestAccessLogMessage m)
  {
    final SearchScope scope = m.getScope();
    if (scope != null)
    {
      AtomicLong scopeCount = searchScopes.get(scope);
      if (scopeCount == null)
      {
        scopeCount = new AtomicLong(0L);
        searchScopes.put(scope, scopeCount);
      }
      scopeCount.incrementAndGet();

      if (! scope.equals(SearchScope.BASE))
      {
        final String filterString = prepareFilter(m.getFilter());
        if (filterString != null)
        {
          AtomicLong filterCount = filterTypes.get(filterString);
          if (filterCount == null)
          {
            filterCount = new AtomicLong(0L);
            filterTypes.put(filterString, filterCount);
          }
          filterCount.incrementAndGet();


          final String baseDN = getDNString(m.getBaseDN());
          if (baseDN != null)
          {
            AtomicLong baseDNCount = searchBaseDNs.get(baseDN);
            if (baseDNCount == null)
            {
              baseDNCount = new AtomicLong(0L);
              searchBaseDNs.put(baseDN, baseDNCount);
            }
            baseDNCount.incrementAndGet();
          }
        }
      }
    }

    final String filterString = m.getFilter();
    if (filterString != null)
    {
      try
      {
        final Filter filter = Filter.create(filterString);
        if (mayRepresentInjectionAttempt(filter))
        {
          filtersRepresentingPotentialInjectionAttempt.add(filter);
        }


        final int numComponents = countComponents(filter);
        final String label;
        if (numComponents == 1)
        {
          label = "1 component";
        }
        else
        {
          label = numComponents + " components";
        }

        AtomicLong count = filterComponentCounts.get(label);
        if (count == null)
        {
          count = new AtomicLong(0L);
          filterComponentCounts.put(label, count);
        }

        count.incrementAndGet();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Indicates whether the provided search filter may represent an injection
   * attempt.  Filters that may represent injection attempts include:
   * <UL>
   *   <LI>Filters with assertion values that contain parentheses, ampersands,
   *       pipes, or single or double quotes.</LI>
   *   <LI>Filters that contain the words "select" and "from".</LI>
   * </UL>
   *
   * @param  filter  The filter to examine.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided filter may represent an injection
   *          attempt, or {@code false} if not.
   */
  static boolean mayRepresentInjectionAttempt(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        for (final Filter f : filter.getComponents())
        {
          if (mayRepresentInjectionAttempt(f))
          {
            return true;
          }
        }
        return false;

      case Filter.FILTER_TYPE_NOT:
        return mayRepresentInjectionAttempt(filter.getNOTComponent());

      case Filter.FILTER_TYPE_EQUALITY:
      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        return mayRepresentInjectionAttempt(filter.getAssertionValue());

      case Filter.FILTER_TYPE_SUBSTRING:
        final String[] subAnyStrings = filter.getSubAnyStrings();
        if (subAnyStrings != null)
        {
          for (final String subAnyString : subAnyStrings)
          {
            if (mayRepresentInjectionAttempt(subAnyString))
            {
              return true;
            }
          }
        }

        return mayRepresentInjectionAttempt(filter.getSubInitialString()) ||
             mayRepresentInjectionAttempt(filter.getSubFinalString());

      case Filter.FILTER_TYPE_PRESENCE:
      default:
        return false;
    }
  }



  /**
   * Indicates whether the provided string (which should be a filter assertion
   * value or substring component) may represent an injection attempt.
   *
   * @param  value  The value for which to make the determination.  It may
   *                optionally be {@code null}.
   *
   * @return  {@code true} if the provided value may represent an injection
   *          attempt, or {@code false} if not.
   */
  private static boolean mayRepresentInjectionAttempt(
               @Nullable final String value)
  {
    if (value == null)
    {
      return false;
    }

    final String lowerValue = StaticUtils.toLowerCase(value);
    return (lowerValue.contains("(") ||
         lowerValue.contains(")") ||
         lowerValue.contains("&") ||
         lowerValue.contains("|") ||
         lowerValue.contains("\"") ||
         lowerValue.contains("'") ||
         ((lowerValue.contains("select") && lowerValue.contains("from"))));
  }



  /**
   * Counts the number of components in the specified filter.  Presence,
   * equality, substring, greater-or-equal, less-or-equal, approximate-match,
   * and extensible-match filters will all be considered a single component.
   * AND and OR filters will be one plus the aggregate component count for each
   * of the components they contain.  NOT filters will be one plus the component
   * count for the filter it contains.
   *
   * @param  filter  The filter for which to count the number of components.  It
   *                 must not be {@code null}.
   *
   * @return  The number of components in the specified filter.
   */
  static int countComponents(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        int count = 1;
        for (final Filter f : filter.getComponents())
        {
          count += countComponents(f);
        }
        return count;

      case Filter.FILTER_TYPE_NOT:
        return 1 + countComponents(filter.getNOTComponent());

      case Filter.FILTER_TYPE_PRESENCE:
      case Filter.FILTER_TYPE_EQUALITY:
      case Filter.FILTER_TYPE_SUBSTRING:
      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
      default:
        return 1;
    }
  }



  /**
   * Performs any necessary processing for an unbind request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processUnbindRequest(
                    @NotNull final UnbindRequestAccessLogMessage m)
  {
    numUnbinds++;
  }



  /**
   * Performs any necessary processing for an add result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processAddResult(@NotNull final AddResultAccessLogMessage m)
  {
    numAdds++;

    updateCommonResult(m);

    updateResultCodeCount(m.getResultCode(), addResultCodes);
    addProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), addProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedAdds++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());
  }



  /**
   * Performs any necessary processing for a bind result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processBindResult(@NotNull final BindResultAccessLogMessage m)
  {
    numBinds++;

    updateCommonResult(m);

    if (m.getAuthenticationType() != null)
    {
      final String authType;
      switch (m.getAuthenticationType())
      {
        case SIMPLE:
          authType = "Simple";
          break;

        case SASL:
          final String saslMechanism = m.getSASLMechanismName();
          if (saslMechanism == null)
          {
            authType = "SASL {unknown mechanism}";
          }
          else
          {
            authType = "SASL " + saslMechanism;
          }
          break;

        case INTERNAL:
          authType = "Internal";
          break;

        default:
          authType = m.getAuthenticationType().name();
          break;
      }

      AtomicLong l = authenticationTypes.get(authType);
      if (l == null)
      {
        l = new AtomicLong(0L);
        authenticationTypes.put(authType, l);
      }
      l.incrementAndGet();
    }

    updateResultCodeCount(m.getResultCode(), bindResultCodes);
    bindProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), bindProcessingTimes);

    String authenticationDN = getDNString(m.getAuthenticationDN());
    if (m.getResultCode() == ResultCode.SUCCESS)
    {
      if (authenticationDN != null)
      {
        AtomicLong l = successfulBindDNs.get(authenticationDN);
        if (l == null)
        {
          l = new AtomicLong(0L);
          successfulBindDNs.put(authenticationDN, l);
        }
        l.incrementAndGet();

        final AtomicLong outstandingFailures =
             outstandingFailedBindDNs.remove(authenticationDN);
        if (outstandingFailures != null)
        {
          final AtomicLong consecutiveFailures =
               consecutiveFailedBindsByDN.get(authenticationDN);
          if ((consecutiveFailures == null) ||
             (outstandingFailures.get() > consecutiveFailures.get()))
          {
            consecutiveFailedBindsByDN.put(authenticationDN,
                 new AtomicLong(outstandingFailures.get()));
          }
        }
      }

      final String ccp = m.getClientConnectionPolicy();
      if (ccp != null)
      {
        AtomicLong l = clientConnectionPolicies.get(ccp);
        if (l == null)
        {
          l = new AtomicLong(0L);
          clientConnectionPolicies.put(ccp, l);
        }
        l.incrementAndGet();
      }
    }
    else if ((m.getResultCode() != ResultCode.SASL_BIND_IN_PROGRESS) &&
         (m.getResultCode() != ResultCode.REFERRAL))
    {
      if (authenticationDN == null)
      {
        authenticationDN = getDNString(m.getDN());
      }

      if (authenticationDN != null)
      {
        AtomicLong l = bindFailuresByDN.get(authenticationDN);
        if (l == null)
        {
          l = new AtomicLong(0L);
          bindFailuresByDN.put(authenticationDN, l);
        }
        l.incrementAndGet();

        l = outstandingFailedBindDNs.get(authenticationDN);
        if (l == null)
        {
          l = new AtomicLong(0L);
          outstandingFailedBindDNs.put(authenticationDN, l);
        }
        l.incrementAndGet();
      }

      String ipAddress = m.getRequesterIPAddress();
      if (ipAddress == null)
      {
        final Long connectionID = m.getConnectionID();
        if (connectionID != null)
        {
          ipAddress = ipAddressesByConnectionID.get(connectionID);
        }
      }

      if (ipAddress != null)
      {
        AtomicLong l = bindFailuresByIPAddress.get(ipAddress);
        if (l == null)
        {
          l = new AtomicLong(0L);
          bindFailuresByIPAddress.put(ipAddress, l);
        }
        l.incrementAndGet();
      }
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedBinds++;
    }

    updateAuthzCount(m.getAuthorizationDN());
  }



  /**
   * Performs any necessary processing for a compare result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processCompareResult(
                    @NotNull final CompareResultAccessLogMessage m)
  {
    numCompares++;

    updateCommonResult(m);

    updateResultCodeCount(m.getResultCode(), compareResultCodes);
    compareProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), compareProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedCompares++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());
  }



  /**
   * Performs any necessary processing for a delete result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processDeleteResult(
                    @NotNull final DeleteResultAccessLogMessage m)
  {
    numDeletes++;

    updateCommonResult(m);

    updateResultCodeCount(m.getResultCode(), deleteResultCodes);
    deleteProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), deleteProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedDeletes++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());
  }



  /**
   * Performs any necessary processing for an extended result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedResult(
                    @NotNull final ExtendedResultAccessLogMessage m)
  {
    numExtended++;

    updateCommonResult(m);

    final String id = m.getConnectionID() + "-" + m.getOperationID();
    if (!processedRequests.remove(id))
    {
      processExtendedRequestInternal(m);
    }

    updateResultCodeCount(m.getResultCode(), extendedResultCodes);
    extendedProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), extendedProcessingTimes);

    final String ccp = m.getClientConnectionPolicy();
    if (ccp != null)
    {
      AtomicLong l = clientConnectionPolicies.get(ccp);
      if (l == null)
      {
        l = new AtomicLong(0L);
        clientConnectionPolicies.put(ccp, l);
      }
      l.incrementAndGet();
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedExtended++;
    }
  }



  /**
   * Performs any necessary processing for a modify result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processModifyResult(
                    @NotNull final ModifyResultAccessLogMessage m)
  {
    numModifies++;

    updateCommonResult(m);

    updateResultCodeCount(m.getResultCode(), modifyResultCodes);
    modifyProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), modifyProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedModifies++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());
  }



  /**
   * Performs any necessary processing for a modify DN result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processModifyDNResult(
                    @NotNull final ModifyDNResultAccessLogMessage m)
  {
    numModifyDNs++;

    updateCommonResult(m);

    updateResultCodeCount(m.getResultCode(), modifyDNResultCodes);
    modifyDNProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), modifyDNProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedModifyDNs++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());
  }



  /**
   * Performs any necessary processing for a search result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchResult(
                    @NotNull final SearchResultAccessLogMessage m)
  {
    numSearches++;

    updateCommonResult(m);

    final String id = m.getConnectionID() + "-" + m.getOperationID();
    if (! processedRequests.remove(id))
    {
      processSearchRequestInternal(m);
    }

    final ResultCode resultCode = m.getResultCode();
    updateResultCodeCount(resultCode, searchResultCodes);
    searchProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), searchProcessingTimes);

    final String filterString = prepareFilter(m.getFilter());

    final Long entryCount = m.getEntriesReturned();
    if (entryCount != null)
    {
      AtomicLong l = searchEntryCounts.get(entryCount);
      if (l == null)
      {
        l = new AtomicLong(0L);
        searchEntryCounts.put(entryCount, l);
      }
      l.incrementAndGet();

      final Map<String,AtomicLong> filterCountMap;
      switch (entryCount.intValue())
      {
        case 0:
          filterCountMap = noEntryFilters;
          break;
        case 1:
          filterCountMap = oneEntryFilters;
          break;
        default:
          filterCountMap = multiEntryFilters;
          break;
      }

      if (filterString != null)
      {
        AtomicLong filterCount = filterCountMap.get(filterString);
        if (filterCount == null)
        {
          filterCount = new AtomicLong(0L);
          filterCountMap.put(filterString, filterCount);
        }
        filterCount.incrementAndGet();
      }
    }

    final Boolean isUnindexed = m.getUnindexed();
    if ((isUnindexed != null) && isUnindexed)
    {
      numUnindexedAttempts++;
      if (resultCode == ResultCode.SUCCESS)
      {
        numUnindexedSuccessful++;
      }
      else
      {
        numUnindexedFailed++;
      }

      if (filterString != null)
      {
        AtomicLong l = unindexedFilters.get(filterString);
        if (l == null)
        {
          l = new AtomicLong(0L);
          unindexedFilters.put(filterString, l);
        }
        l.incrementAndGet();
      }
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedSearches++;
    }

    updateAuthzCount(m.getAlternateAuthorizationDN());

    final Double processingTimeMillis = m.getProcessingTimeMillis();
    if ((processingTimeMillis != null) && (filterString != null))
    {
      final long processingTimeMicros =
           Math.round(processingTimeMillis * 1_000.0);

      AtomicLong l = mostExpensiveFilters.get(filterString);
      if (l == null)
      {
        l = new AtomicLong(processingTimeMicros);
        mostExpensiveFilters.put(filterString, l);
      }
      else
      {
        final long previousProcessingTimeMicros = l.get();
        if (processingTimeMicros > previousProcessingTimeMicros)
        {
          l.set(processingTimeMicros);
        }
      }
    }
  }



  /**
   * Updates a number of statistics that are common to all types of result log
   * messages.
   *
   * @param  m  The result log message to examine.
   */
  private void updateCommonResult(
                    @NotNull final OperationResultAccessLogMessage m)
  {
    // Handle the work queue wait time.
    totalWorkQueueWaitTime +=
         doubleValue(m.getWorkQueueWaitTimeMillis(), workQueueWaitTimes);


    // Handle request and response control OIDs.
    for (final String oid : m.getRequestControlOIDs())
    {
      numRequestControls++;
      updateCount(requestControlOIDs, oid);
    }

    for (final String oid : m.getResponseControlOIDs())
    {
      numResponseControls++;
      updateCount(responseControlOIDs, oid);
    }


    // Handle used and missing privileges.
    for (final String privilegeName : m.getPreAuthorizationUsedPrivileges())
    {
      updateCount(preAuthzPrivilegesUsed, privilegeName);
    }

    for (final String privilegeName : m.getUsedPrivileges())
    {
      updateCount(privilegesUsed, privilegeName);
    }

    for (final String privilegeName : m.getMissingPrivileges())
    {
      updateCount(privilegesMissing, privilegeName);
    }
  }



  /**
   * Updates the counter for the given key in the provided map.  If the key does
   * not exist, it will be added to the map.
   *
   * @param  m    The map to be updated.
   * @param  key  The key for which to update the count.
   */
  private static void updateCount(@NotNull final Map<String,AtomicLong> m,
                                  @NotNull final String key)
  {
    AtomicLong count = m.get(key);
    if (count == null)
    {
      count = new AtomicLong(0L);
      m.put(key, count);
    }

    count.incrementAndGet();
  }



  /**
   * Updates the count for the provided result code in the given map.
   *
   * @param  rc  The result code for which to update the count.
   * @param  m   The map used to hold counts by result code.
   */
  private static void updateResultCodeCount(@Nullable final ResultCode rc,
                           @NotNull final HashMap<ResultCode,AtomicLong> m)
  {
    if (rc == null)
    {
      return;
    }

    AtomicLong l = m.get(rc);
    if (l == null)
    {
      l = new AtomicLong(0L);
      m.put(rc, l);
    }
    l.incrementAndGet();
  }



  /**
   * Retrieves the double value for the provided {@code Double} object.
   *
   * @param  d  The {@code Double} object for which to retrieve the value.
   * @param  m  The processing time histogram map to be updated.
   *
   * @return  The double value of the provided {@code Double} object if it was
   *          non-{@code null}, or 0.0 if it was {@code null}.
   */
  private static double doubleValue(@Nullable final Double d,
                                    @NotNull final HashMap<Long,AtomicLong> m)
  {
    if (d == null)
    {
      return 0.0;
    }
    else
    {
      for (final Map.Entry<Long,AtomicLong> e : m.entrySet())
      {
        if (d <= e.getKey())
        {
          e.getValue().incrementAndGet();
          break;
        }
      }

      return d;
    }
  }



  /**
   * Updates the provided list with the most frequently-occurring elements in
   * the provided map, paired with the number of times each value occurred.
   *
   * @param  <K>                    The type of object used as the key for the
   *                                provided map.
   * @param  countMap               The map to be examined.  It is expected that
   *                                the values of the map will be the count of
   *                                occurrences for the keys.
   * @param  mostCommonElementList  The list to which the values will be
   *                                updated.  It must not be {@code null}, must
   *                                be empty, and must be updatable.
   * @param  maxListSize            The maximum number of items to add to the
   *                                provided list.  It must be greater than
   *                                zero.
   * @param  skippedWithSameCount   A counter that will be incremented for each
   *                                map entry that is skipped with the same
   *                                count as a value that was not skipped.  It
   *                                must not be {@code null} and must initially
   *                                be zero.
   * @param  skippedWithLowerCount  A counter that will be incremented for each
   *                                map entry that is skipped with a lower count
   *                                as the last value that was not skipped.  It
   *                                must not be {@code null} and must initially
   *                                be zero.
   *
   * @return  A list of the most frequently-occurring elements in the provided
   *          map.
   */
  @NotNull()
  private static <K> List<ObjectPair<K,Long>> getMostCommonElements(
               @NotNull final Map<K,AtomicLong> countMap,
               @NotNull final List<ObjectPair<K,Long>> mostCommonElementList,
               final int maxListSize,
               @NotNull final AtomicLong skippedWithSameCount,
               @NotNull final AtomicLong skippedWithLowerCount)
  {
    final TreeMap<Long,List<K>> reverseMap =
         new TreeMap<>(new ReverseComparator<Long>());
    for (final Map.Entry<K,AtomicLong> e : countMap.entrySet())
    {
      final Long count = e.getValue().get();
      List<K> list = reverseMap.get(count);
      if (list == null)
      {
        list = new ArrayList<>();
        reverseMap.put(count, list);
      }
      list.add(e.getKey());
    }

    for (final Map.Entry<Long,List<K>> e : reverseMap.entrySet())
    {
      final Long l = e.getKey();
      int numNotSkipped = 0;
      for (final K k : e.getValue())
      {
        if (mostCommonElementList.size() >= maxListSize)
        {
          if (numNotSkipped > 0)
          {
            skippedWithSameCount.incrementAndGet();
          }
          else
          {
            skippedWithLowerCount.incrementAndGet();
          }
        }
        else
        {
          numNotSkipped++;
          mostCommonElementList.add(new ObjectPair<>(k, l));
        }
      }
    }

    return mostCommonElementList;
  }



  /**
   * Updates the count of alternate authorization identities for the provided
   * DN.
   *
   * @param  authzDN  The DN of the alternate authorization identity that was
   *                  used.  It may be {@code null} if no alternate
   *                  authorization identity was used.
   */
  private void updateAuthzCount(@Nullable final String authzDN)
  {
    if (authzDN == null)
    {
      return;
    }

    final String dnString = getDNString(authzDN);

    AtomicLong l = authzDNs.get(dnString);
    if (l == null)
    {
      l = new AtomicLong(0L);
      authzDNs.put(dnString, l);
    }
  }



  /**
   * Retrieves a string representation of the provided DN.  It may either be
   * anonymized, using question marks in place of specific attribute values, or
   * it may be the actual string representation of the given DN.
   *
   * @param  dn  The DN for which to retrieve the string representation.
   *
   * @return  A string representation of the provided DN, or {@code null} if the
   *          given DN was {@code null}.
   */
  @Nullable()
  private String getDNString(@Nullable final String dn)
  {
    if (dn == null)
    {
      return null;
    }

    final DN parsedDN;
    try
    {
      parsedDN = new DN(dn);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return dn.toLowerCase();
    }

    if (parsedDN.isNullDN())
    {
      return "{Null DN}";
    }

    if (doNotAnonymize.isPresent())
    {
      return parsedDN.toNormalizedString();
    }

    final StringBuilder buffer = new StringBuilder();
    final RDN[] rdns = parsedDN.getRDNs();
    for (int i=0; i < rdns.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      final RDN rdn = rdns[i];
      final String[] attributeNames = rdn.getAttributeNames();
      for (int j=0; j < attributeNames.length; j++)
      {
        if (j > 0)
        {
          buffer.append('+');
        }
        buffer.append(attributeNames[j].toLowerCase());
        buffer.append("=?");
      }
    }

    return buffer.toString();
  }



  /**
   * Retrieves a prepared string representation of the provided search filter.
   * It may potentially be de-anonymized to include specific values.
   *
   * @param  filterString  The string representation of the filter to prepare.
   *                       It may be {@code null} if the log message does not
   *                       have a filter.
   *
   * @return  A string representation of the provided filter (which may or may
   *          not be anonymized), or {@code null} if the provided filter is
   *          {@code null} or cannot be prepared.
   */
  @Nullable()
  private String prepareFilter(@Nullable final String filterString)
  {
    if (filterString == null)
    {
      return null;
    }

    if (doNotAnonymize.isPresent())
    {
      return filterString.toLowerCase();
    }

    try
    {
      return new GenericFilter(Filter.create(filterString)).toString().
           toLowerCase();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Writes a breakdown of the processing times for a specified type of
   * operation.
   *
   * @param  t  The name of the operation type.
   * @param  n  The total number of operations of the specified type that were
   *            processed by the server.
   * @param  m  The map of operation counts by processing time bucket.
   */
  private void printProcessingTimeHistogram(@NotNull final String t,
                    final long n,
                    @NotNull final LinkedHashMap<Long,AtomicLong> m)
  {
    printHistogram("Count of " + t + " operations by processing time:", n, m);
  }



  /**
   * Writes a breakdown of the processing times for a specified type of
   * operation.
   *
   * @param  h  The header to display at the beginning of the histogram.
   * @param  n  The total number of operations that were processed by the
   *            server.
   * @param  m  The map of operation counts by processing time bucket.
   */
  private void printHistogram(@NotNull final String h,
                    final long n,
                    @NotNull final LinkedHashMap<Long,AtomicLong> m)
  {
    if (n <= 0)
    {
      return;
    }

    out();
    out(h);

    long lowerBound = 0;
    long accumulatedCount = 0;
    final Iterator<Map.Entry<Long,AtomicLong>> i = m.entrySet().iterator();
    while (i.hasNext())
    {
      final Map.Entry<Long,AtomicLong> e = i.next();
      final long upperBound = e.getKey();
      final long count = e.getValue().get();
      final double categoryPercent = 100.0 * count / n;

      accumulatedCount += count;
      final double accumulatedPercent = 100.0 * accumulatedCount / n;

      if (i.hasNext())
      {
        final String lowerBoundString;
        if (lowerBound == 0L)
        {
          lowerBoundString = "0 milliseconds";
        }
        else
        {
          final long lowerBoundNanos = lowerBound * 1_000_000L;
          lowerBoundString = DurationArgument.nanosToDuration(lowerBoundNanos);
        }

        final long upperBoundNanos = upperBound * 1_000_000L;
        final String upperBoundString =
             DurationArgument.nanosToDuration(upperBoundNanos);


        out("Between ", lowerBoundString, " and ", upperBoundString, ":  ",
            count, " (", decimalFormat.format(categoryPercent), "%, ",
            decimalFormat.format(accumulatedPercent), "% accumulated)");
        lowerBound = upperBound;
      }
      else
      {
        final long lowerBoundNanos = lowerBound * 1_000_000L;
        final String lowerBoundString =
             DurationArgument.nanosToDuration(lowerBoundNanos);

        out("Greater than ", lowerBoundString, ":  ", count, " (",
            decimalFormat.format(categoryPercent), "%, ",
            decimalFormat.format(accumulatedPercent), "% accumulated)");
      }
    }
  }



  /**
   * Optionally prints information about the number and percent of operations of
   * the specified type that involved access to uncached data.
   *
   * @param  operationType  The type of operation.
   * @param  numUncached    The number of operations of the specified type that
   *                        involved access to uncached data.
   * @param  numTotal       The total number of operations of the specified
   *                        type.
   */
  private void printUncached(@NotNull final String operationType,
                             final long numUncached,
                             final long numTotal)
  {
    if (numUncached == 0)
    {
      return;
    }

    out(operationType, ":  ", numUncached, " (",
         decimalFormat.format(100.0 * numUncached / numTotal), "%)");
  }



  /**
   * Prints data from the provided map of counts.
   *
   * @param  countMap      The map containing the data to print.
   * @param  heading       The heading to display before printing the contents
   *                       of the map.
   * @param  singularItem  The name to use for a single item represented by the
   *                       key of the given map.
   * @param  pluralItem    The name to use for zero or multiple items
   *                       represented by the key of the given map.
   */
  private void printCounts(@Nullable final Map<String,AtomicLong> countMap,
                           @NotNull final String heading,
                           @NotNull final String singularItem,
                           @NotNull final String pluralItem)
  {
    if ((countMap == null) || countMap.isEmpty())
    {
      return;
    }

    long totalCount = 0L;
    for (final AtomicLong l : countMap.values())
    {
      totalCount += l.get();
    }

    out();
    out(heading);

    int displayCount = reportCount.getValue();
    if (displayCount <= 0L)
    {
      displayCount = Integer.MAX_VALUE;
    }

    final List<ObjectPair<String,Long>> countList = new ArrayList<>();
    final AtomicLong skippedWithSameCount = new AtomicLong(0L);
    final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
    getMostCommonElements(countMap, countList, displayCount,
         skippedWithSameCount, skippedWithLowerCount);

    long count = -1L;
    for (final ObjectPair<String,Long> p : countList)
    {
      count = p.getSecond();

      if (totalCount > 0L)
      {
        final double percent = 100.0 * count / totalCount;
        out(p.getFirst(), ":  ", count, " (", decimalFormat.format(percent),
             ")");
      }
      else
      {
        out(p.getFirst(), ":  ", count);
      }
    }

    if (skippedWithSameCount.get() > 0L)
    {
      out("{ Skipped " + skippedWithSameCount.get() + " additional " +
           getSingularOrPlural(skippedWithSameCount.get(), singularItem,
                pluralItem) +
           " with a count of " + count + " }");
    }

    if (skippedWithLowerCount.get() > 0L)
    {
      out("{ Skipped " + skippedWithLowerCount.get() + " additional " +
           getSingularOrPlural(skippedWithLowerCount.get(), singularItem,
                pluralItem) +
           " with a count that is less than " + count + " }");
    }
  }



  /**
   * Prints data from the provided map of counts.
   *
   * @param  countMap       The map containing the data to print.
   * @param  operationType  The type of operation represented by the keys of
   *                        the map.
   */
  private void printResultCodeCounts(
                    @Nullable final Map<ResultCode,AtomicLong> countMap,
                    @NotNull final String operationType)
  {
    if ((countMap == null) || countMap.isEmpty())
    {
      return;
    }

    long totalCount = 0L;
    for (final AtomicLong l : countMap.values())
    {
      totalCount += l.get();
    }

    out();
    out("Most common " + operationType + " operation result codes:");

    int displayCount = reportCount.getValue();
    if (displayCount <= 0L)
    {
      displayCount = Integer.MAX_VALUE;
    }

    final List<ObjectPair<ResultCode,Long>> resultCodeList = new ArrayList<>();
    final AtomicLong skippedWithSameCount = new AtomicLong(0L);
    final AtomicLong skippedWithLowerCount = new AtomicLong(0L);
    getMostCommonElements(countMap, resultCodeList, displayCount,
         skippedWithSameCount, skippedWithLowerCount);

    long count = -1L;
    for (final ObjectPair<ResultCode,Long> p : resultCodeList)
    {
      count = p.getSecond();

      if (totalCount > 0L)
      {
        final double percent = 100.0 * count / totalCount;
        out(p.getFirst().getName(), " (", p.getFirst().intValue(), "):  ",
             count, " (", decimalFormat.format(percent), ")");
      }
      else
      {
        out(p.getFirst(), ":  ", count);
      }
    }

    if (skippedWithSameCount.get() > 0L)
    {
      out("{ Skipped " + skippedWithSameCount.get() + " additional result " +
           getSingularOrPlural(skippedWithSameCount.get(), "code", "codes") +
           " with a count of " + count + " }");
    }

    if (skippedWithLowerCount.get() > 0L)
    {
      out("{ Skipped " + skippedWithLowerCount.get() + " additional result " +
           getSingularOrPlural(skippedWithLowerCount.get(), "code", "codes") +
           " with a count that is less than " + count + " }");
    }
  }



  /**
   * Retrieves the appropriate singular or plural form based on the given
   * value.
   *
   * @param  count     The count that will be used to determine whether to
   *                   retrieve the singular or plural form.
   * @param  singular  The singular form for the value to return.
   * @param  plural    The plural form for the value to return.
   *
   * @return  The singular form if the count is 1, or the plural form if the
   *          count is any other value.
   */
  @NotNull()
  private String getSingularOrPlural(final long count,
                                     @NotNull final String singular,
                                     @NotNull final String plural)
  {
    if (count == 1L)
    {
      return singular;
    }
    else
    {
      return plural;
    }
  }
}
