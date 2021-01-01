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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.DNFileReader;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.FilterFileReader;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.RateAdjustor;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IPAddressArgumentValueValidator;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.TimestampArgument;
import com.unboundid.util.args.SubCommand;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a tool that can be used to perform a variety of account
 * management functions against user entries in the Ping Identity, UnboundID,
 * or Nokia/Alcatel-Lucent 8661 Directory Server.  It primarily uses the
 * password policy state extended operation for its processing.
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
public final class ManageAccount
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The primary name of the argument used to indicate that the tool should
   * append to the reject file rather than overwrite it.
   */
  @NotNull private static final String ARG_APPEND_TO_REJECT_FILE =
       "appendToRejectFile";



  /**
   * The primary name of the argument used to specify a base DN to use for
   * searches.
   */
  @NotNull static final String ARG_BASE_DN = "baseDN";



  /**
   * The primary name of the argument used to specify the path to a file to a
   * sample variable rate data file to create.
   */
  @NotNull private static final String ARG_GENERATE_SAMPLE_RATE_FILE =
       "generateSampleRateFile";



  /**
   * The primary name of the argument used to specify the path to a file
   * containing the DNs of the users on which to operate.
   */
  @NotNull private static final String ARG_DN_INPUT_FILE = "dnInputFile";



  /**
   * The primary name of the argument used to specify the path to a file
   * containing search filters to use to identify users.
   */
  @NotNull private static final String ARG_FILTER_INPUT_FILE =
       "filterInputFile";



  /**
   * The primary name of the argument used to specify the number of threads to
   * use to process search operations to identify which users to target.
   */
  @NotNull static final String ARG_NUM_SEARCH_THREADS = "numSearchThreads";



  /**
   * The primary name of the argument used to specify the number of threads to
   * use to perform manage-account processing.
   */
  @NotNull static final String ARG_NUM_THREADS = "numThreads";



  /**
   * The primary name of the argument used to specify the target rate of
   * operations per second.
   */
  @NotNull private static final String ARG_RATE_PER_SECOND = "ratePerSecond";



  /**
   * The primary name of the argument used to specify the path to a reject file
   * to create.
   */
  @NotNull private static final String ARG_REJECT_FILE = "rejectFile";



  /**
   * The primary name of the argument used to specify the simple page size to
   * use when performing searches.
   */
  @NotNull static final String ARG_SIMPLE_PAGE_SIZE = "simplePageSize";



  /**
   * The primary name of the argument used to suppress result operation types
   * without values.
   */
  @NotNull static final String ARG_SUPPRESS_EMPTY_RESULT_OPERATIONS =
       "suppressEmptyResultOperations";



  /**
   * The primary name of the argument used to specify the DN of the user on
   * which to operate.
   */
  @NotNull private static final String ARG_TARGET_DN = "targetDN";



  /**
   * The primary name of the argument used to specify a search filter to use to
   * identify users.
   */
  @NotNull private static final String ARG_TARGET_FILTER = "targetFilter";



  /**
   * The primary name of the argument used to specify the user IDs of target
   * users.
   */
  @NotNull private static final String ARG_TARGET_USER_ID = "targetUserID";



  /**
   * The primary name of the argument used to specify the name of the attribute
   * to identify which user has a given user ID.
   */
  @NotNull static final String ARG_USER_ID_ATTRIBUTE = "userIDAttribute";



  /**
   * The primary name of the argument used to specify the path to a file
   * containing the user IDs of the target users.
   */
  @NotNull private static final String ARG_USER_ID_INPUT_FILE =
       "userIDInputFile";



  /**
   * The primary name of the argument used to specify the path to a variable
   * rate data file.
   */
  @NotNull private static final String ARG_VARIABLE_RATE_DATA =
       "variableRateData";



  /**
   * The default search base DN.
   */
  @NotNull private static final DN DEFAULT_BASE_DN = DN.NULL_DN;



  /**
   * The default user ID attribute.
   */
  @NotNull private static final String DEFAULT_USER_ID_ATTRIBUTE = "uid";



  /**
   * A target user DN to use in examples.
   */
  @NotNull private static final String EXAMPLE_TARGET_USER_DN =
       "uid=jdoe,ou=People,dc=example,dc=com";



  // The argument parser for this tool.
  @Nullable private volatile ArgumentParser parser;

  // Indicates whether all DNs have been provided to the manage-account
  // processor.
  @NotNull private final AtomicBoolean allDNsProvided;

  // Indicates whether all filters have been provided to the manage-account
  // search processor.
  @NotNull private final AtomicBoolean allFiltersProvided;

  // Indicates whether a request has been made to cancel processing.
  @NotNull private final AtomicBoolean cancelRequested;

  // The rate limiter to use for this tool.
  @Nullable private volatile FixedRateBarrier rateLimiter;

  // The LDAP connection options to use for connections created by this tool.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // The LDIF writer to use to write information about successful and failed
  // operations.
  @Nullable private volatile LDIFWriter outputWriter;

  // The LDIF writer to use to write information about failed operations.
  @Nullable private volatile LDIFWriter rejectWriter;

  // The search processor for this tool.
  @Nullable private volatile ManageAccountSearchProcessor searchProcessor;

  // The rate adjustor to use to vary the load over time.
  @Nullable private volatile RateAdjustor rateAdjustor;



  /**
   * Invokes the tool with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this tool.
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
   * Invokes the tool with the provided set of arguments.
   *
   * @param  out   The output stream to use for standard out.  It may be
   *               {@code null} if standard out should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this tool.
   *
   * @return  A result code with the status of the tool processing.  Any result
   *          code other than {@link ResultCode#SUCCESS} should be considered a
   *          failure.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final ManageAccount tool = new ManageAccount(out, err);

    final boolean origCommentAboutBase64EncodedValues =
         LDIFWriter.commentAboutBase64EncodedValues();
    LDIFWriter.setCommentAboutBase64EncodedValues(true);
    try
    {
      return tool.runTool(args);
    }
    finally
    {
      LDIFWriter.setCommentAboutBase64EncodedValues(
           origCommentAboutBase64EncodedValues);
    }
  }



  /**
   * Creates a new instance of this tool with the provided arguments.
   *
   * @param  out  The output stream to use for standard out.  It may be
   *              {@code null} if standard out should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public ManageAccount(@Nullable final OutputStream out,
                       @Nullable final OutputStream err)
  {
    super(out, err);

    connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setUnsolicitedNotificationHandler(this);

    allDNsProvided = new AtomicBoolean(false);
    allFiltersProvided = new AtomicBoolean(false);
    cancelRequested = new AtomicBoolean(false);

    parser = null;
    rateLimiter = null;
    rateAdjustor = null;
    outputWriter = null;
    rejectWriter = null;
    searchProcessor = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "manage-account";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_MANAGE_ACCT_TOOL_DESC.get();
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
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsAuthentication()
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
  protected boolean supportsSASLHelp()
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
  protected boolean supportsMultipleServers()
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
    // Get a copy of the argument parser for later use.
    this.parser = parser;


    // Get the current time formatted as a generalized time.
    final String currentGeneralizedTime =
         StaticUtils.encodeGeneralizedTime(System.currentTimeMillis());
    final String olderGeneralizedTime =
         StaticUtils.encodeGeneralizedTime(
              System.currentTimeMillis() - 12_345L);


    // Define the global arguments used to indicate which users to target.
    final DNArgument targetDN = new DNArgument('b', ARG_TARGET_DN, false, 0,
         null, INFO_MANAGE_ACCT_ARG_DESC_TARGET_DN.get());
    targetDN.addLongIdentifier("userDN", true);
    targetDN.addLongIdentifier("target-dn", true);
    targetDN.addLongIdentifier("user-dn", true);
    targetDN.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(targetDN);

    final FileArgument dnInputFile = new FileArgument(null, ARG_DN_INPUT_FILE,
         false, 0, null, INFO_MANAGE_ACCT_ARG_DESC_DN_FILE.get(), true,
         true, true, false);
    dnInputFile.addLongIdentifier("targetDNFile", true);
    dnInputFile.addLongIdentifier("userDNFile", true);
    dnInputFile.addLongIdentifier("dn-input-file", true);
    dnInputFile.addLongIdentifier("target-dn-file", true);
    dnInputFile.addLongIdentifier("user-dn-file", true);
    dnInputFile.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(dnInputFile);

    final FilterArgument targetFilter = new FilterArgument(null,
         ARG_TARGET_FILTER, false, 0, null,
         INFO_MANAGE_ACCT_ARG_DESC_TARGET_FILTER.get(ARG_BASE_DN));
    targetFilter.addLongIdentifier("target-filter", true);
    targetFilter.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(targetFilter);

    final FileArgument filterInputFile = new FileArgument(null,
         ARG_FILTER_INPUT_FILE, false, 0, null,
         INFO_MANAGE_ACCT_ARG_DESC_FILTER_INPUT_FILE.get(ARG_BASE_DN),
         true, true, true, false);
    filterInputFile.addLongIdentifier("targetFilterFile", true);
    filterInputFile.addLongIdentifier("filter-input-file", true);
    filterInputFile.addLongIdentifier("target-filter-file", true);
    filterInputFile.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(filterInputFile);

    final StringArgument targetUserID = new StringArgument(null,
         ARG_TARGET_USER_ID, false, 0, null,
         INFO_MANAGE_ACCT_ARG_DESC_TARGET_USER_ID.get(ARG_BASE_DN,
              ARG_USER_ID_ATTRIBUTE));
    targetUserID.addLongIdentifier("userID", true);
    targetUserID.addLongIdentifier("target-user-id", true);
    targetUserID.addLongIdentifier("user-id", true);
    targetUserID.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(targetUserID);

    final FileArgument userIDInputFile = new FileArgument(null,
         ARG_USER_ID_INPUT_FILE, false, 0, null,
         INFO_MANAGE_ACCT_ARG_DESC_USER_ID_INPUT_FILE.get(ARG_BASE_DN,
              ARG_USER_ID_ATTRIBUTE),
         true, true, true, false);
    userIDInputFile.addLongIdentifier("targetUserIDFile", true);
    userIDInputFile.addLongIdentifier("user-id-input-file", true);
    userIDInputFile.addLongIdentifier("target-user-id-file", true);
    userIDInputFile.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(userIDInputFile);

    final StringArgument userIDAttribute = new StringArgument(null,
         ARG_USER_ID_ATTRIBUTE, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_USER_ID_ATTR.get(
              ARG_TARGET_USER_ID, ARG_USER_ID_INPUT_FILE,
              DEFAULT_USER_ID_ATTRIBUTE),
         DEFAULT_USER_ID_ATTRIBUTE);
    userIDAttribute.addLongIdentifier("user-id-attribute", true);
    userIDAttribute.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(userIDAttribute);

    final DNArgument baseDN = new DNArgument(null, ARG_BASE_DN, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_BASE_DN.get(ARG_TARGET_FILTER,
              ARG_FILTER_INPUT_FILE, ARG_TARGET_USER_ID,
              ARG_USER_ID_INPUT_FILE),
         DEFAULT_BASE_DN);
    baseDN.addLongIdentifier("base-dn", true);
    baseDN.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get());
    parser.addArgument(baseDN);

    final IntegerArgument simplePageSize = new IntegerArgument('z',
         ARG_SIMPLE_PAGE_SIZE, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_SIMPLE_PAGE_SIZE.get(getToolName()), 1,
         Integer.MAX_VALUE);
    simplePageSize.addLongIdentifier("simple-page-size", true);
    simplePageSize.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_TARGET_USER_ARGS.get(getToolName()));
    parser.addArgument(simplePageSize);


    // Ensure that the user will be required ot provide at least one of the
    // arguments to specify which users to target.
    parser.addRequiredArgumentSet(targetDN, dnInputFile, targetFilter,
         filterInputFile, targetUserID, userIDInputFile);


    // Define the global arguments used to control the amount of load the tool
    // should be permitted to generate.
    final IntegerArgument numThreads = new IntegerArgument('t', ARG_NUM_THREADS,
         false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_NUM_THREADS.get(getToolName()), 1,
         Integer.MAX_VALUE, 1);
    numThreads.addLongIdentifier("num-threads", true);
    numThreads.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_PERFORMANCE.get());
    parser.addArgument(numThreads);

    final IntegerArgument numSearchThreads = new IntegerArgument(null,
         ARG_NUM_SEARCH_THREADS, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_NUM_SEARCH_THREADS.get(getToolName()), 1,
         Integer.MAX_VALUE, 1);
    numSearchThreads.addLongIdentifier("num-search-threads", true);
    numSearchThreads.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_PERFORMANCE.get());
    parser.addArgument(numSearchThreads);

    final IntegerArgument ratePerSecond = new IntegerArgument('r',
         ARG_RATE_PER_SECOND, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_RATE_PER_SECOND.get(
              ARG_VARIABLE_RATE_DATA),
         1, Integer.MAX_VALUE);
    ratePerSecond.addLongIdentifier("rate-per-second", true);
    ratePerSecond.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_PERFORMANCE.get());
    parser.addArgument(ratePerSecond);

    final FileArgument variableRateData = new FileArgument(null,
         ARG_VARIABLE_RATE_DATA, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_VARIABLE_RATE_DATA.get(
              ARG_RATE_PER_SECOND),
         true, true, true, false);
    variableRateData.addLongIdentifier("variable-rate-data", true);
    variableRateData.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_PERFORMANCE.get());
    parser.addArgument(variableRateData);

    final FileArgument generateSampleRateFile = new FileArgument(null,
         ARG_GENERATE_SAMPLE_RATE_FILE, false, 1, null,
         INFO_MANAGE_ACCT_ARG_DESC_GENERATE_SAMPLE_RATE_FILE.get(
              ARG_VARIABLE_RATE_DATA),
         false, true, true, false);
    generateSampleRateFile.addLongIdentifier("generate-sample-rate-file", true);
    generateSampleRateFile.setArgumentGroupName(
         INFO_MANAGE_ACCT_ARG_GROUP_PERFORMANCE.get());
    generateSampleRateFile.setUsageArgument(true);
    parser.addArgument(generateSampleRateFile);


    // Define the global arguments tht pertain to the reject file.
    final FileArgument rejectFile = new FileArgument('R', ARG_REJECT_FILE,
         false, 1, null, INFO_MANAGE_ACCT_ARG_DESC_REJECT_FILE.get(),
         false, true, true, false);
    rejectFile.addLongIdentifier("reject-file", true);
    parser.addArgument(rejectFile);

    final BooleanArgument appendToRejectFile = new BooleanArgument(null,
         ARG_APPEND_TO_REJECT_FILE, 1,
         INFO_MANAGE_ACCT_ARG_DESC_APPEND_TO_REJECT_FILE.get(
              rejectFile.getIdentifierString()));
    appendToRejectFile.addLongIdentifier("append-to-reject-file", true);
    parser.addArgument(appendToRejectFile);

    parser.addDependentArgumentSet(appendToRejectFile, rejectFile);


    // Define the argument used to suppress result operations without values.
    final BooleanArgument suppressEmptyResultOperations =
         new BooleanArgument(null, ARG_SUPPRESS_EMPTY_RESULT_OPERATIONS,
              1,
              INFO_MANAGE_ACCT_ARG_DESC_SUPPRESS_EMPTY_RESULT_OPERATIONS.get(
                   getToolName()));
    parser.addArgument(suppressEmptyResultOperations);


    // Define the subcommand used to retrieve all state information for a user.
    createSubCommand(ManageAccountSubCommandType.GET_ALL,
         INFO_MANAGE_ACCT_SC_GET_ALL_EXAMPLE.get(EXAMPLE_TARGET_USER_DN));


    // Define the subcommand used to retrieve the password policy DN for a user.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_POLICY_DN,
         INFO_MANAGE_ACCT_SC_GET_POLICY_DN_EXAMPLE.get(EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether the account is usable.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_USABLE,
         INFO_MANAGE_ACCT_SC_GET_IS_USABLE_EXAMPLE.get(EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the set of password policy state
    // account usability notice messages.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_USABILITY_NOTICES,
         INFO_MANAGE_ACCT_SC_GET_USABILITY_NOTICES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the set of password policy state
    // account usability warning messages.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_USABILITY_WARNINGS,
         INFO_MANAGE_ACCT_SC_GET_USABILITY_WARNINGS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the set of password policy state
    // account usability error messages.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_USABILITY_ERRORS,
         INFO_MANAGE_ACCT_SC_GET_USABILITY_ERRORS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the password changed time for a user.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_CHANGED_TIME,
         INFO_MANAGE_ACCT_SC_GET_PW_CHANGED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the password changed time for a user.
    final ArgumentParser setPWChangedTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_PASSWORD_CHANGED_TIME);

    final TimestampArgument setPWChangedTimeValueArg = new TimestampArgument(
         'O', "passwordChangedTime", false, 1, null,
         INFO_MANAGE_ACCT_SC_SET_PW_CHANGED_TIME_ARG_VALUE.get());
    setPWChangedTimeValueArg.addLongIdentifier("operationValue", true);
    setPWChangedTimeValueArg.addLongIdentifier("password-changed-time", true);
    setPWChangedTimeValueArg.addLongIdentifier("operation-value", true);
    setPWChangedTimeParser.addArgument(setPWChangedTimeValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_PASSWORD_CHANGED_TIME,
         setPWChangedTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_PASSWORD_CHANGED_TIME,
              INFO_MANAGE_ACCT_SC_SET_PW_CHANGED_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--passwordChangedTime", currentGeneralizedTime));


    // Define the subcommand to clear the password changed time for a user.
    createSubCommand(ManageAccountSubCommandType.CLEAR_PASSWORD_CHANGED_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_PW_CHANGED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user account is disabled.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_DISABLED,
         INFO_MANAGE_ACCT_SC_GET_IS_DISABLED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to specify whether a user's account is disabled.
    final ArgumentParser setAcctDisabledParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_DISABLED);

    final BooleanValueArgument setAcctDisabledValueArg =
         new BooleanValueArgument('O', "accountIsDisabled", true, null,
              INFO_MANAGE_ACCT_SC_SET_IS_DISABLED_ARG_VALUE.get());
    setAcctDisabledValueArg.addLongIdentifier("operationValue", true);
    setAcctDisabledValueArg.addLongIdentifier("account-is-disabled", true);
    setAcctDisabledValueArg.addLongIdentifier("operation-value", true);
    setAcctDisabledParser.addArgument(setAcctDisabledValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_ACCOUNT_IS_DISABLED,
         setAcctDisabledParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_DISABLED,
              INFO_MANAGE_ACCT_SC_SET_IS_DISABLED_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN),
              "--accountIsDisabled", "true"));


    // Define the subcommand to clear the account disabled state.
    createSubCommand(ManageAccountSubCommandType.CLEAR_ACCOUNT_IS_DISABLED,
         INFO_MANAGE_ACCT_SC_CLEAR_IS_DISABLED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the account activation time for a user.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_ACTIVATION_TIME,
         INFO_MANAGE_ACCT_SC_GET_ACCT_ACT_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the account activation time for a user.
    final ArgumentParser setAcctActivationTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_ACCOUNT_ACTIVATION_TIME);

    final TimestampArgument setAcctActivationTimeValueArg =
         new TimestampArgument('O', "accountActivationTime", false, 1, null,
              INFO_MANAGE_ACCT_SC_SET_ACCT_ACT_TIME_ARG_VALUE.get());
    setAcctActivationTimeValueArg.addLongIdentifier("operationValue", true);
    setAcctActivationTimeValueArg.addLongIdentifier("account-activation-time",
         true);
    setAcctActivationTimeValueArg.addLongIdentifier("operation-value", true);
    setAcctActivationTimeParser.addArgument(setAcctActivationTimeValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_ACCOUNT_ACTIVATION_TIME,
         setAcctActivationTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_ACCOUNT_ACTIVATION_TIME,
              INFO_MANAGE_ACCT_SC_SET_ACCT_ACT_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--accountActivationTime", currentGeneralizedTime));


    // Define the subcommand to clear the account activation time for a user.
    createSubCommand(ManageAccountSubCommandType.CLEAR_ACCOUNT_ACTIVATION_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_ACCT_ACT_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the length of time until a user's
    // account is activated.
    createSubCommand(
         ManageAccountSubCommandType.GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_ACCT_ACT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user's account is not yet
    // active.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_NOT_YET_ACTIVE,
         INFO_MANAGE_ACCT_SC_GET_ACCT_NOT_YET_ACTIVE_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the account expiration time for a user.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_EXPIRATION_TIME,
         INFO_MANAGE_ACCT_SC_GET_ACCT_EXP_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the account expiration time for a user.
    final ArgumentParser setAcctExpirationTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_ACCOUNT_EXPIRATION_TIME);

    final TimestampArgument setAcctExpirationTimeValueArg =
         new TimestampArgument('O', "accountExpirationTime", false, 1, null,
              INFO_MANAGE_ACCT_SC_SET_ACCT_EXP_TIME_ARG_VALUE.get());
    setAcctExpirationTimeValueArg.addLongIdentifier("operationValue", true);
    setAcctExpirationTimeValueArg.addLongIdentifier("account-expiration-time",
         true);
    setAcctExpirationTimeValueArg.addLongIdentifier("operation-value", true);
    setAcctExpirationTimeParser.addArgument(setAcctExpirationTimeValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_ACCOUNT_EXPIRATION_TIME,
         setAcctExpirationTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_ACCOUNT_EXPIRATION_TIME,
              INFO_MANAGE_ACCT_SC_SET_ACCT_EXP_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--accountExpirationTime", currentGeneralizedTime));


    // Define the subcommand to clear the account expiration time for a user.
    createSubCommand(ManageAccountSubCommandType.CLEAR_ACCOUNT_EXPIRATION_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_ACCT_EXP_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the length of time until a user's
    // account is expired.
    createSubCommand(
         ManageAccountSubCommandType.GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_ACCT_EXP_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user's account is expired.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_EXPIRED,
         INFO_MANAGE_ACCT_SC_GET_ACCT_IS_EXPIRED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve a user's password expiration warned
    // time.
    createSubCommand(
         ManageAccountSubCommandType.GET_PASSWORD_EXPIRATION_WARNED_TIME,
         INFO_MANAGE_ACCT_SC_GET_PW_EXP_WARNED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set a user's password expiration warned time.
    final ArgumentParser setPWExpWarnedTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_PASSWORD_EXPIRATION_WARNED_TIME);

    final TimestampArgument setPWExpWarnedTimeValueArg =
         new TimestampArgument('O', "passwordExpirationWarnedTime", false, 1,
              null, INFO_MANAGE_ACCT_SC_SET_PW_EXP_WARNED_TIME_ARG_VALUE.get());
    setPWExpWarnedTimeValueArg.addLongIdentifier("operationValue", true);
    setPWExpWarnedTimeValueArg.addLongIdentifier(
         "password-expiration-warned-time", true);
    setPWExpWarnedTimeValueArg.addLongIdentifier("operation-value", true);
    setPWExpWarnedTimeParser.addArgument(setPWExpWarnedTimeValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_PASSWORD_EXPIRATION_WARNED_TIME,
         setPWExpWarnedTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_PASSWORD_EXPIRATION_WARNED_TIME,
              INFO_MANAGE_ACCT_SC_SET_PW_EXP_WARNED_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--passwordExpirationWarnedTime", currentGeneralizedTime));


    // Define the subcommand to clear a user's password expiration warned time.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_PASSWORD_EXPIRATION_WARNED_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_PW_EXP_WARNED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the number of seconds until a user is
    // eligible to receive a password expiration warning.
    createSubCommand(
         ManageAccountSubCommandType.
              GET_SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_PW_EXP_WARNING_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve a user's password expiration time.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_EXPIRATION_TIME,
         INFO_MANAGE_ACCT_SC_GET_PW_EXP_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the number of seconds until a user's
    // password expires.
    createSubCommand(
         ManageAccountSubCommandType.GET_SECONDS_UNTIL_PASSWORD_EXPIRATION,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_PW_EXP_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user's password is expired.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_IS_EXPIRED,
         INFO_MANAGE_ACCT_SC_GET_PW_IS_EXPIRED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether an account is failure locked.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_FAILURE_LOCKED,
         INFO_MANAGE_ACCT_SC_GET_ACCT_FAILURE_LOCKED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to specify whether an account is failure locked.
    final ArgumentParser setIsFailureLockedParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_FAILURE_LOCKED);

    final BooleanValueArgument setIsFailureLockedValueArg =
         new BooleanValueArgument('O', "accountIsFailureLocked", true, null,
              INFO_MANAGE_ACCT_SC_SET_ACCT_FAILURE_LOCKED_ARG_VALUE.get());
    setIsFailureLockedValueArg.addLongIdentifier("operationValue", true);
    setIsFailureLockedValueArg.addLongIdentifier("account-is-failure-locked",
         true);
    setIsFailureLockedValueArg.addLongIdentifier("operation-value", true);
    setIsFailureLockedParser.addArgument(setIsFailureLockedValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_ACCOUNT_IS_FAILURE_LOCKED,
         setIsFailureLockedParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_FAILURE_LOCKED,
              INFO_MANAGE_ACCT_SC_SET_ACCT_FAILURE_LOCKED_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN),
              "--accountIsFailureLocked", "true"));


    // Define the subcommand to get the time an account was failure locked.
    createSubCommand(ManageAccountSubCommandType.GET_FAILURE_LOCKOUT_TIME,
         INFO_MANAGE_ACCT_SC_GET_FAILURE_LOCKED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the length of time until a failure-locked
    // account will be automatically unlocked.
    createSubCommand(
         ManageAccountSubCommandType.
              GET_SECONDS_UNTIL_AUTHENTICATION_FAILURE_UNLOCK,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_FAILURE_UNLOCK_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine the authentication failure times.
    createSubCommand(
         ManageAccountSubCommandType.GET_AUTHENTICATION_FAILURE_TIMES,
         INFO_MANAGE_ACCT_SC_GET_AUTH_FAILURE_TIMES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to add values to the set of authentication failure
    // times.
    final ArgumentParser addAuthFailureTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.ADD_AUTHENTICATION_FAILURE_TIME);

    final TimestampArgument addAuthFailureTimeValueArg =
         new TimestampArgument('O', "authenticationFailureTime", false, 0, null,
              INFO_MANAGE_ACCT_SC_ADD_AUTH_FAILURE_TIME_ARG_VALUE.get());
    addAuthFailureTimeValueArg.addLongIdentifier("operationValue", true);
    addAuthFailureTimeValueArg.addLongIdentifier(
         "authentication-failure-time", true);
    addAuthFailureTimeValueArg.addLongIdentifier("operation-value", true);
    addAuthFailureTimeParser.addArgument(addAuthFailureTimeValueArg);

    createSubCommand(
         ManageAccountSubCommandType.ADD_AUTHENTICATION_FAILURE_TIME,
         addAuthFailureTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.ADD_AUTHENTICATION_FAILURE_TIME,
              INFO_MANAGE_ACCT_SC_ADD_AUTH_FAILURE_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN)));


    // Define the subcommand to replace the authentication failure times.
    final ArgumentParser setAuthFailureTimesParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_AUTHENTICATION_FAILURE_TIMES);

    final TimestampArgument setAuthFailureTimesValueArg =
         new TimestampArgument('O', "authenticationFailureTime", false, 0, null,
              INFO_MANAGE_ACCT_SC_SET_AUTH_FAILURE_TIMES_ARG_VALUE.get());
    setAuthFailureTimesValueArg.addLongIdentifier("operationValue", true);
    setAuthFailureTimesValueArg.addLongIdentifier(
         "authentication-failure-time", true);
    setAuthFailureTimesValueArg.addLongIdentifier("operation-value", true);
    setAuthFailureTimesParser.addArgument(setAuthFailureTimesValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_AUTHENTICATION_FAILURE_TIMES,
         setAuthFailureTimesParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_AUTHENTICATION_FAILURE_TIMES,
              INFO_MANAGE_ACCT_SC_SET_AUTH_FAILURE_TIMES_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, olderGeneralizedTime,
                   currentGeneralizedTime),
              "--authenticationFailureTime", olderGeneralizedTime,
              "--authenticationFailureTime", currentGeneralizedTime));


    // Define the subcommand to clear the authentication failure times.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_AUTHENTICATION_FAILURE_TIMES,
         INFO_MANAGE_ACCT_SC_CLEAR_AUTH_FAILURE_TIMES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the remaining authentication failure count.
    createSubCommand(
         ManageAccountSubCommandType.GET_REMAINING_AUTHENTICATION_FAILURE_COUNT,
         INFO_MANAGE_ACCT_SC_GET_REMAINING_FAILURE_COUNT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether the account is idle locked.
    createSubCommand(ManageAccountSubCommandType.GET_ACCOUNT_IS_IDLE_LOCKED,
         INFO_MANAGE_ACCT_SC_GET_ACCT_IDLE_LOCKED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the length of time until the account is
    // idle locked.
    createSubCommand(ManageAccountSubCommandType.GET_SECONDS_UNTIL_IDLE_LOCKOUT,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_IDLE_LOCKOUT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the idle lockout time for an account.
    createSubCommand(ManageAccountSubCommandType.GET_IDLE_LOCKOUT_TIME,
         INFO_MANAGE_ACCT_SC_GET_IDLE_LOCKOUT_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user's password has been
    // reset.
    createSubCommand(ManageAccountSubCommandType.GET_MUST_CHANGE_PASSWORD,
         INFO_MANAGE_ACCT_SC_GET_MUST_CHANGE_PW_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to specify whether a user's password has been
    // reset.
    final ArgumentParser setPWIsResetParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_MUST_CHANGE_PASSWORD);

    final BooleanValueArgument setPWIsResetValueArg =
         new BooleanValueArgument('O', "mustChangePassword", true, null,
              INFO_MANAGE_ACCT_SC_SET_MUST_CHANGE_PW_ARG_VALUE.get());
    setPWIsResetValueArg.addLongIdentifier("passwordIsReset", true);
    setPWIsResetValueArg.addLongIdentifier("operationValue", true);
    setPWIsResetValueArg.addLongIdentifier("must-change-password", true);
    setPWIsResetValueArg.addLongIdentifier("password-is-reset", true);
    setPWIsResetValueArg.addLongIdentifier("operation-value", true);
    setPWIsResetParser.addArgument(setPWIsResetValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_MUST_CHANGE_PASSWORD,
         setPWIsResetParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_MUST_CHANGE_PASSWORD,
              INFO_MANAGE_ACCT_SC_SET_MUST_CHANGE_PW_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN),
              "--mustChangePassword", "true"));


    // Define the subcommand to clear the password reset state information.
    createSubCommand(ManageAccountSubCommandType.CLEAR_MUST_CHANGE_PASSWORD,
         INFO_MANAGE_ACCT_SC_CLEAR_MUST_CHANGE_PW_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether the account is reset locked.
    createSubCommand(
         ManageAccountSubCommandType.GET_ACCOUNT_IS_PASSWORD_RESET_LOCKED,
         INFO_MANAGE_ACCT_SC_GET_ACCT_IS_RESET_LOCKED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the length of time until the password is
    // reset locked.
    createSubCommand(
         ManageAccountSubCommandType.GET_SECONDS_UNTIL_PASSWORD_RESET_LOCKOUT,
         INFO_MANAGE_ACCT_SC_GET_SECONDS_UNTIL_RESET_LOCKOUT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the password reset lockout time.
    createSubCommand(
         ManageAccountSubCommandType.GET_PASSWORD_RESET_LOCKOUT_TIME,
         INFO_MANAGE_ACCT_SC_GET_RESET_LOCKOUT_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the last login time.
    createSubCommand(ManageAccountSubCommandType.GET_LAST_LOGIN_TIME,
         INFO_MANAGE_ACCT_SC_GET_LAST_LOGIN_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the last login time.
    final ArgumentParser setLastLoginTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_LAST_LOGIN_TIME);

    final TimestampArgument setLastLoginTimeValueArg = new TimestampArgument(
         'O', "lastLoginTime", false, 1, null,
         INFO_MANAGE_ACCT_SC_SET_LAST_LOGIN_TIME_ARG_VALUE.get());
    setLastLoginTimeValueArg.addLongIdentifier("operationValue", true);
    setLastLoginTimeValueArg.addLongIdentifier("last-login-time", true);
    setLastLoginTimeValueArg.addLongIdentifier("operation-value", true);
    setLastLoginTimeParser.addArgument(setLastLoginTimeValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_LAST_LOGIN_TIME,
         setLastLoginTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_LAST_LOGIN_TIME,
              INFO_MANAGE_ACCT_SC_SET_LAST_LOGIN_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--lastLoginTime", currentGeneralizedTime));


    // Define the subcommand to clear the last login time.
    createSubCommand(ManageAccountSubCommandType.CLEAR_LAST_LOGIN_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_LAST_LOGIN_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the last login IP address.
    createSubCommand(ManageAccountSubCommandType.GET_LAST_LOGIN_IP_ADDRESS,
         INFO_MANAGE_ACCT_SC_GET_LAST_LOGIN_IP_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the last login IP address.
    final ArgumentParser setLastLoginIPParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_LAST_LOGIN_IP_ADDRESS);

    final StringArgument setLastLoginIPValueArg = new StringArgument('O',
         "lastLoginIPAddress", true, 1, null,
         INFO_MANAGE_ACCT_SC_SET_LAST_LOGIN_IP_ARG_VALUE.get());
    setLastLoginIPValueArg.addLongIdentifier("operationValue", true);
    setLastLoginIPValueArg.addLongIdentifier("last-login-ip-address", true);
    setLastLoginIPValueArg.addLongIdentifier("operation-value", true);
    setLastLoginIPValueArg.addValueValidator(
         new IPAddressArgumentValueValidator());
    setLastLoginIPParser.addArgument(setLastLoginIPValueArg);


    createSubCommand(ManageAccountSubCommandType.SET_LAST_LOGIN_IP_ADDRESS,
         setLastLoginIPParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_LAST_LOGIN_IP_ADDRESS,
              INFO_MANAGE_ACCT_SC_SET_LAST_LOGIN_IP_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, "1.2.3.4"),
              "--lastLoginIPAddress", "1.2.3.4"));


    // Define the subcommand to clear the last login IP address.
    createSubCommand(ManageAccountSubCommandType.CLEAR_LAST_LOGIN_IP_ADDRESS,
         INFO_MANAGE_ACCT_SC_CLEAR_LAST_LOGIN_IP_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the grace login use times.
    createSubCommand(ManageAccountSubCommandType.GET_GRACE_LOGIN_USE_TIMES,
         INFO_MANAGE_ACCT_SC_GET_GRACE_LOGIN_TIMES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to add values to the set of grace login use times.
    final ArgumentParser addGraceLoginTimeParser =
         createSubCommandParser(
              ManageAccountSubCommandType.ADD_GRACE_LOGIN_USE_TIME);

    final TimestampArgument addGraceLoginTimeValueArg =
         new TimestampArgument('O', "graceLoginUseTime", false, 0, null,
              INFO_MANAGE_ACCT_SC_ADD_GRACE_LOGIN_TIME_ARG_VALUE.get());
    addGraceLoginTimeValueArg.addLongIdentifier("operationValue", true);
    addGraceLoginTimeValueArg.addLongIdentifier("grace-login-use-time", true);
    addGraceLoginTimeValueArg.addLongIdentifier("operation-value", true);
    addGraceLoginTimeParser.addArgument(addGraceLoginTimeValueArg);

    createSubCommand(ManageAccountSubCommandType.ADD_GRACE_LOGIN_USE_TIME,
         addGraceLoginTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.ADD_GRACE_LOGIN_USE_TIME,
              INFO_MANAGE_ACCT_SC_ADD_GRACE_LOGIN_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN)));


    // Define the subcommand to replace the set of grace login use times.
    final ArgumentParser setGraceLoginTimesParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_GRACE_LOGIN_USE_TIMES);

    final TimestampArgument setGraceLoginTimesValueArg =
         new TimestampArgument('O', "graceLoginUseTime", false, 0, null,
              INFO_MANAGE_ACCT_SC_SET_GRACE_LOGIN_TIMES_ARG_VALUE.get());
    setGraceLoginTimesValueArg.addLongIdentifier("operationValue", true);
    setGraceLoginTimesValueArg.addLongIdentifier("grace-login-use-time", true);
    setGraceLoginTimesValueArg.addLongIdentifier("operation-value", true);
    setGraceLoginTimesParser.addArgument(setGraceLoginTimesValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_GRACE_LOGIN_USE_TIMES,
         setGraceLoginTimesParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_GRACE_LOGIN_USE_TIMES,
              INFO_MANAGE_ACCT_SC_SET_GRACE_LOGIN_TIMES_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, olderGeneralizedTime,
                   currentGeneralizedTime),
              "--graceLoginUseTime", olderGeneralizedTime,
              "--graceLoginUseTime", currentGeneralizedTime));


    // Define the subcommand to clear the grace login use times.
    createSubCommand(ManageAccountSubCommandType.CLEAR_GRACE_LOGIN_USE_TIMES,
         INFO_MANAGE_ACCT_SC_CLEAR_GRACE_LOGIN_TIMES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the remaining grace login count.
    createSubCommand(
         ManageAccountSubCommandType.GET_REMAINING_GRACE_LOGIN_COUNT,
         INFO_MANAGE_ACCT_SC_GET_REMAINING_GRACE_LOGIN_COUNT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the password changed by required time value.
    createSubCommand(
         ManageAccountSubCommandType.GET_PASSWORD_CHANGED_BY_REQUIRED_TIME,
         INFO_MANAGE_ACCT_SC_GET_PW_CHANGED_BY_REQ_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the password changed by required time value.
    final ArgumentParser setPWChangedByReqTimeParser =
         createSubCommandParser(ManageAccountSubCommandType.
              SET_PASSWORD_CHANGED_BY_REQUIRED_TIME);

    final TimestampArgument setPWChangedByReqTimeValueArg =
         new TimestampArgument('O', "passwordChangedByRequiredTime", false, 1,
              null,
              INFO_MANAGE_ACCT_SC_SET_PW_CHANGED_BY_REQ_TIME_ARG_VALUE.get());
    setPWChangedByReqTimeValueArg.addLongIdentifier("operationValue", true);
    setPWChangedByReqTimeValueArg.addLongIdentifier(
         "password-changed-by-required-time", true);
    setPWChangedByReqTimeValueArg.addLongIdentifier("operation-value", true);
    setPWChangedByReqTimeParser.addArgument(
         setPWChangedByReqTimeValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_PASSWORD_CHANGED_BY_REQUIRED_TIME,
         setPWChangedByReqTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_PASSWORD_CHANGED_BY_REQUIRED_TIME,
              INFO_MANAGE_ACCT_SC_SET_PW_CHANGED_BY_REQ_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN)));


    // Define the subcommand to clear the password changed by required time
    // value.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_PASSWORD_CHANGED_BY_REQUIRED_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_PW_CHANGED_BY_REQ_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the length of time until the required change
    // time.
    createSubCommand(
         ManageAccountSubCommandType.
              GET_SECONDS_UNTIL_REQUIRED_PASSWORD_CHANGE_TIME,
         INFO_MANAGE_ACCT_SC_GET_SECS_UNTIL_REQ_CHANGE_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the password history count.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_HISTORY_COUNT,
         INFO_MANAGE_ACCT_SC_GET_PW_HISTORY_COUNT_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to clear a user's password history.
    createSubCommand(ManageAccountSubCommandType.CLEAR_PASSWORD_HISTORY,
         INFO_MANAGE_ACCT_SC_CLEAR_PW_HISTORY_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user has a retired password.
    createSubCommand(ManageAccountSubCommandType.GET_HAS_RETIRED_PASSWORD,
         INFO_MANAGE_ACCT_SC_GET_HAS_RETIRED_PW_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the time that a user's former password
    // was retired.
    createSubCommand(ManageAccountSubCommandType.GET_PASSWORD_RETIRED_TIME,
         INFO_MANAGE_ACCT_SC_GET_PW_RETIRED_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the retired password expiration time.
    createSubCommand(
         ManageAccountSubCommandType.GET_RETIRED_PASSWORD_EXPIRATION_TIME,
         INFO_MANAGE_ACCT_SC_GET_RETIRED_PW_EXP_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to purge a retired password.
    createSubCommand(ManageAccountSubCommandType.CLEAR_RETIRED_PASSWORD,
         INFO_MANAGE_ACCT_SC_PURGE_RETIRED_PW_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the available SASL mechanisms for a user.
    createSubCommand(ManageAccountSubCommandType.GET_AVAILABLE_SASL_MECHANISMS,
         INFO_MANAGE_ACCT_SC_GET_AVAILABLE_SASL_MECHS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the available OTP delivery mechanisms for a
    // user.
    createSubCommand(
         ManageAccountSubCommandType.GET_AVAILABLE_OTP_DELIVERY_MECHANISMS,
         INFO_MANAGE_ACCT_SC_GET_AVAILABLE_OTP_MECHS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user has at least one TOTP
    // shared secret.
    createSubCommand(ManageAccountSubCommandType.GET_HAS_TOTP_SHARED_SECRET,
         INFO_MANAGE_ACCT_SC_GET_HAS_TOTP_SHARED_SECRET_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to add a value to the set of TOTP shared secrets
    // for a user.
    final ArgumentParser addTOTPSharedSecretParser =
         createSubCommandParser(
              ManageAccountSubCommandType.ADD_TOTP_SHARED_SECRET);

    final StringArgument addTOTPSharedSecretValueArg =
         new StringArgument('O', "totpSharedSecret", true, 0, null,
              INFO_MANAGE_ACCT_SC_ADD_YUBIKEY_ID_ARG_VALUE.get());
    addTOTPSharedSecretValueArg.addLongIdentifier("operationValue", true);
    addTOTPSharedSecretValueArg.addLongIdentifier("totp-shared-secret", true);
    addTOTPSharedSecretValueArg.addLongIdentifier("operation-value", true);
    addTOTPSharedSecretValueArg.setSensitive(true);
    addTOTPSharedSecretParser.addArgument(
         addTOTPSharedSecretValueArg);

    createSubCommand(ManageAccountSubCommandType.ADD_TOTP_SHARED_SECRET,
         addTOTPSharedSecretParser,
         createSubCommandExample(
              ManageAccountSubCommandType.ADD_TOTP_SHARED_SECRET,
              INFO_MANAGE_ACCT_SC_ADD_TOTP_SHARED_SECRET_EXAMPLE.get(
                   "abcdefghijklmnop", EXAMPLE_TARGET_USER_DN),
              "--totpSharedSecret", "abcdefghijklmnop"));


    // Define the subcommand to remove a value from the set of TOTP shared
    // secrets for a user.
    final ArgumentParser removeTOTPSharedSecretParser =
         createSubCommandParser(
              ManageAccountSubCommandType.REMOVE_TOTP_SHARED_SECRET);

    final StringArgument removeTOTPSharedSecretValueArg =
         new StringArgument('O', "totpSharedSecret", true, 0, null,
              INFO_MANAGE_ACCT_SC_REMOVE_YUBIKEY_ID_ARG_VALUE.get());
    removeTOTPSharedSecretValueArg.addLongIdentifier("operationValue", true);
    removeTOTPSharedSecretValueArg.addLongIdentifier("totp-shared-secret",
         true);
    removeTOTPSharedSecretValueArg.addLongIdentifier("operation-value", true);
    removeTOTPSharedSecretValueArg.setSensitive(true);
    removeTOTPSharedSecretParser.addArgument(
         removeTOTPSharedSecretValueArg);

    createSubCommand(ManageAccountSubCommandType.REMOVE_TOTP_SHARED_SECRET,
         removeTOTPSharedSecretParser,
         createSubCommandExample(
              ManageAccountSubCommandType.REMOVE_TOTP_SHARED_SECRET,
              INFO_MANAGE_ACCT_SC_REMOVE_TOTP_SHARED_SECRET_EXAMPLE.get(
                   "abcdefghijklmnop", EXAMPLE_TARGET_USER_DN),
              "--totpSharedSecret", "abcdefghijklmnop"));


    // Define the subcommand to replace set of TOTP shared secrets for a user.
    final ArgumentParser setTOTPSharedSecretsParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_TOTP_SHARED_SECRETS);

    final StringArgument setTOTPSharedSecretsValueArg =
         new StringArgument('O', "totpSharedSecret", true, 0, null,
              INFO_MANAGE_ACCT_SC_SET_TOTP_SHARED_SECRETS_ARG_VALUE.get());
    setTOTPSharedSecretsValueArg.addLongIdentifier("operationValue", true);
    setTOTPSharedSecretsValueArg.addLongIdentifier("totp-shared-secret", true);
    setTOTPSharedSecretsValueArg.addLongIdentifier("operation-value", true);
    setTOTPSharedSecretsValueArg.setSensitive(true);
    setTOTPSharedSecretsParser.addArgument(
         setTOTPSharedSecretsValueArg);

    createSubCommand(ManageAccountSubCommandType.SET_TOTP_SHARED_SECRETS,
         setTOTPSharedSecretsParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_TOTP_SHARED_SECRETS,
              INFO_MANAGE_ACCT_SC_SET_TOTP_SHARED_SECRETS_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, "abcdefghijklmnop"),
              "--totpSharedSecret", "abcdefghijklmnop"));


    // Define the subcommand to clear the set of TOTP shared secrets for a user.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_TOTP_SHARED_SECRETS,
         INFO_MANAGE_ACCT_SC_CLEAR_TOTP_SHARED_SECRETS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user has at least one
    // registered YubiKey OTP device public ID.
    createSubCommand(
         ManageAccountSubCommandType.GET_HAS_REGISTERED_YUBIKEY_PUBLIC_ID,
         INFO_MANAGE_ACCT_SC_GET_HAS_YUBIKEY_ID_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to get the set of registered YubiKey OTP device
    // public IDs for a user.
    createSubCommand(
         ManageAccountSubCommandType.GET_REGISTERED_YUBIKEY_PUBLIC_IDS,
         INFO_MANAGE_ACCT_SC_GET_YUBIKEY_IDS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to add a value to the set of registered YubiKey OTP
    // device public IDs for a user.
    final ArgumentParser addRegisteredYubiKeyPublicIDParser =
         createSubCommandParser(
              ManageAccountSubCommandType.ADD_REGISTERED_YUBIKEY_PUBLIC_ID);

    final StringArgument addRegisteredYubiKeyPublicIDValueArg =
         new StringArgument('O', "publicID", true, 0, null,
              INFO_MANAGE_ACCT_SC_ADD_YUBIKEY_ID_ARG_VALUE.get());
    addRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operationValue",
         true);
    addRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("public-id", true);
    addRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operation-value",
         true);
    addRegisteredYubiKeyPublicIDParser.addArgument(
         addRegisteredYubiKeyPublicIDValueArg);

    createSubCommand(
         ManageAccountSubCommandType.ADD_REGISTERED_YUBIKEY_PUBLIC_ID,
         addRegisteredYubiKeyPublicIDParser,
         createSubCommandExample(
              ManageAccountSubCommandType.ADD_REGISTERED_YUBIKEY_PUBLIC_ID,
              INFO_MANAGE_ACCT_SC_ADD_YUBIKEY_ID_EXAMPLE.get(
                   "abcdefghijkl", EXAMPLE_TARGET_USER_DN),
              "--publicID", "abcdefghijkl"));


    // Define the subcommand to remove a value from the set of registered
    // YubiKey OTP device public IDs for a user.
    final ArgumentParser removeRegisteredYubiKeyPublicIDParser =
         createSubCommandParser(
              ManageAccountSubCommandType.REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID);

    final StringArgument removeRegisteredYubiKeyPublicIDValueArg =
         new StringArgument('O', "publicID", true, 0, null,
              INFO_MANAGE_ACCT_SC_REMOVE_YUBIKEY_ID_ARG_VALUE.get());
    removeRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operationValue",
         true);
    removeRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("public-id",
         true);
    removeRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operation-value",
         true);
    removeRegisteredYubiKeyPublicIDParser.addArgument(
         removeRegisteredYubiKeyPublicIDValueArg);

    createSubCommand(
         ManageAccountSubCommandType.REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID,
         removeRegisteredYubiKeyPublicIDParser,
         createSubCommandExample(
              ManageAccountSubCommandType.REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID,
              INFO_MANAGE_ACCT_SC_REMOVE_YUBIKEY_ID_EXAMPLE.get(
                   "abcdefghijkl", EXAMPLE_TARGET_USER_DN),
              "--publicID", "abcdefghijkl"));


    // Define the subcommand to replace set of registered YubiKey OTP device
    // public IDs for a user.
    final ArgumentParser setRegisteredYubiKeyPublicIDParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_REGISTERED_YUBIKEY_PUBLIC_IDS);

    final StringArgument setRegisteredYubiKeyPublicIDValueArg =
         new StringArgument('O', "publicID", true, 0, null,
              INFO_MANAGE_ACCT_SC_SET_YUBIKEY_IDS_ARG_VALUE.get());
    setRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operationValue",
         true);
    setRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("public-id", true);
    setRegisteredYubiKeyPublicIDValueArg.addLongIdentifier("operation-value",
         true);
    setRegisteredYubiKeyPublicIDParser.addArgument(
         setRegisteredYubiKeyPublicIDValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_REGISTERED_YUBIKEY_PUBLIC_IDS,
         setRegisteredYubiKeyPublicIDParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_REGISTERED_YUBIKEY_PUBLIC_IDS,
              INFO_MANAGE_ACCT_SC_SET_YUBIKEY_IDS_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, "abcdefghijkl"),
              "--publicID", "abcdefghijkl"));


    // Define the subcommand to clear the set of registered YubiKey OTP device
    // public IDs for a user.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS,
         INFO_MANAGE_ACCT_SC_CLEAR_YUBIKEY_IDS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether a user has at least one static
    // password.
    createSubCommand(ManageAccountSubCommandType.GET_HAS_STATIC_PASSWORD,
         INFO_MANAGE_ACCT_SC_GET_HAS_STATIC_PW_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the last bind password validation time
    // for a user.
    createSubCommand(
         ManageAccountSubCommandType.GET_LAST_BIND_PASSWORD_VALIDATION_TIME,
         INFO_MANAGE_ACCT_SC_GET_LAST_BIND_PW_VALIDATION_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve the length of time since the last bind
    // password validation for a user.
    createSubCommand(
         ManageAccountSubCommandType.
              GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION,
         INFO_MANAGE_ACCT_SC_GET_SECS_SINCE_LAST_BIND_PW_VALIDATION_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to set the last bind password validation time for a
    // user.
    final ArgumentParser setLastBindPasswordValidationTimeParser =
         createSubCommandParser(ManageAccountSubCommandType.
              SET_LAST_BIND_PASSWORD_VALIDATION_TIME);

    final TimestampArgument setLastBindPasswordValidationTimeValueArg =
         new TimestampArgument('O', "validationTime", false, 1, null,
              INFO_MANAGE_ACCT_SC_SET_LAST_BIND_PW_VALIDATION_TIME_ARG_VALUE.
                   get());
    setLastBindPasswordValidationTimeValueArg.addLongIdentifier(
         "operationValue", true);
    setLastBindPasswordValidationTimeValueArg.addLongIdentifier(
         "validation-time", true);
    setLastBindPasswordValidationTimeValueArg.addLongIdentifier(
         "operation-value", true);
    setLastBindPasswordValidationTimeParser.addArgument(
         setLastBindPasswordValidationTimeValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_LAST_BIND_PASSWORD_VALIDATION_TIME,
         setLastBindPasswordValidationTimeParser,
         createSubCommandExample(
              ManageAccountSubCommandType.
                   SET_LAST_BIND_PASSWORD_VALIDATION_TIME,
              INFO_MANAGE_ACCT_SC_SET_LAST_BIND_PW_VALIDATION_TIME_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN, currentGeneralizedTime),
              "--validationTime", currentGeneralizedTime));


    // Define the subcommand to clear the last bind password validation time for
    // a user.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME,
         INFO_MANAGE_ACCT_SC_CLEAR_LAST_BIND_PW_VALIDATION_TIME_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to determine whether an account is locked because
    // it contains a password that does not satisfy all of the configured
    // password validators.
    createSubCommand(
         ManageAccountSubCommandType.GET_ACCOUNT_IS_VALIDATION_LOCKED,
         INFO_MANAGE_ACCT_SC_GET_ACCT_VALIDATION_LOCKED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to specify whether an account is locked because it
    // contains a password that does not satisfy all of the configured password
    // validators.
    final ArgumentParser setIsValidationLockedParser =
         createSubCommandParser(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_VALIDATION_LOCKED);

    final BooleanValueArgument setIsValidationLockedValueArg =
         new BooleanValueArgument('O', "accountIsValidationLocked", true, null,
              INFO_MANAGE_ACCT_SC_SET_ACCT_VALIDATION_LOCKED_ARG_VALUE.get());
    setIsValidationLockedValueArg.addLongIdentifier("operationValue", true);
    setIsValidationLockedValueArg.addLongIdentifier(
         "account-is-validation-locked", true);
    setIsValidationLockedValueArg.addLongIdentifier("operation-value", true);
    setIsValidationLockedParser.addArgument(setIsValidationLockedValueArg);

    createSubCommand(
         ManageAccountSubCommandType.SET_ACCOUNT_IS_VALIDATION_LOCKED,
         setIsValidationLockedParser,
         createSubCommandExample(
              ManageAccountSubCommandType.SET_ACCOUNT_IS_VALIDATION_LOCKED,
              INFO_MANAGE_ACCT_SC_SET_ACCT_VALIDATION_LOCKED_EXAMPLE.get(
                   EXAMPLE_TARGET_USER_DN),
              "--accountIsValidationLocked", "true"));


    // Define the subcommand to retrieve a user's recent login history.
    createSubCommand(
         ManageAccountSubCommandType.GET_RECENT_LOGIN_HISTORY,
         INFO_MANAGE_ACCT_SC_GET_RECENT_LOGIN_HISTORY_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));


    // Define the subcommand to retrieve a user's recent login history.
    createSubCommand(
         ManageAccountSubCommandType.CLEAR_RECENT_LOGIN_HISTORY,
         INFO_MANAGE_ACCT_SC_CLEAR_RECENT_LOGIN_HISTORY_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));
  }



  /**
   * Creates an argument parser for the provided subcommand type.  It will not
   * have any arguments associated with it.
   *
   * @param  type  The subcommand type for which to create the argument parser.
   *
   * @return  The created argument parser.
   *
   * @throws  ArgumentException  If a problem is encountered while creating the
   *                             argument parser.
   */
  @NotNull()
  private static ArgumentParser createSubCommandParser(
               @NotNull final ManageAccountSubCommandType type)
          throws ArgumentException
  {
    return new ArgumentParser(type.getPrimaryName(), type.getDescription());
  }



  /**
   * Generates an example usage map for a specified subcommand.
   *
   * @param  t            The subcommand type.
   * @param  description  The description to use for the example.
   * @param  args         The set of arguments to include in the example,
   *                      excluding the subcommand name and the arguments used
   *                      to connect and authenticate to the server.  This may
   *                      be empty if no additional arguments are needed.
   *
   * @return The generated example usage map.
   */
  @NotNull()
  private static LinkedHashMap<String[],String> createSubCommandExample(
               @NotNull final ManageAccountSubCommandType t,
               @NotNull final String description,
               @NotNull final String... args)
  {
    final LinkedHashMap<String[], String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    createSubCommandExample(examples, t, description, args);
    return examples;
  }



  /**
   * Adds an example for a specified subcommand to the given map.
   *
   * @param  examples     The map to which the example should be added.
   * @param  t            The subcommand type.
   * @param  description  The description to use for the example.
   * @param  args         The set of arguments to include in the example,
   *                      excluding the subcommand name and the arguments used
   *                      to connect and authenticate to the server.  This may
   *                      be empty if no additional arguments are needed.
   */
  private static void createSubCommandExample(
       @NotNull final LinkedHashMap<String[], String> examples,
       @NotNull final ManageAccountSubCommandType t, final
       @NotNull String description,
       @NotNull final String... args)
  {
    final ArrayList<String> argList = new ArrayList<>(10 + args.length);
    argList.add(t.getPrimaryName());
    argList.add("--hostname");
    argList.add("server.example.com");
    argList.add("--port");
    argList.add("389");
    argList.add("--bindDN");
    argList.add("uid=admin,dc=example,dc=com");
    argList.add("--promptForBindPassword");
    argList.add("--targetDN");
    argList.add("uid=jdoe,ou=People,dc=example,dc=com");

    if (args.length > 0)
    {
      argList.addAll(Arrays.asList(args));
    }

    final String[] argArray = new String[argList.size()];
    argList.toArray(argArray);

    examples.put(argArray, description);
  }



  /**
   * Creates a subcommand with the provided information.
   *
   * @param  subcommandType       The subcommand type.
   * @param  exampleDescription   The description to use for the
   *                              automatically-generated example.
   *
   * @throws  ArgumentException  If a problem is encountered while creating the
   *                             subcommand.
   */
  private void createSubCommand(
                    @NotNull final ManageAccountSubCommandType subcommandType,
                    @NotNull final String exampleDescription)
          throws ArgumentException
  {
    final ArgumentParser subcommandParser =
         createSubCommandParser(subcommandType);

    final LinkedHashMap<String[],String> examples =
         createSubCommandExample(subcommandType, exampleDescription);

    createSubCommand(subcommandType, subcommandParser, examples);
  }



  /**
   * Creates a subcommand with the provided information.
   *
   * @param  subcommandType    The subcommand type.
   * @param  subcommandParser  The argument parser for the subcommand-specific
   *                           arguments.
   * @param  examples          The example usages for the subcommand.
   *
   * @throws  ArgumentException  If a problem is encountered while creating the
   *                             subcommand.
   */
  private void createSubCommand(
                    @NotNull final ManageAccountSubCommandType subcommandType,
                    @NotNull final ArgumentParser subcommandParser,
                    @NotNull final LinkedHashMap<String[],String> examples)
          throws ArgumentException
  {
    final SubCommand subCommand = new SubCommand(
         subcommandType.getPrimaryName(), subcommandType.getDescription(),
         subcommandParser, examples);

    for (final String alternateName : subcommandType.getAlternateNames())
    {
      subCommand.addName(alternateName, true);
    }

    parser.addSubCommand(subCommand);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // If we should just generate a sample rate data file, then do that now.
    final FileArgument generateSampleRateFile =
         parser.getFileArgument(ARG_GENERATE_SAMPLE_RATE_FILE);
    if (generateSampleRateFile.isPresent())
    {
      try
      {
        RateAdjustor.writeSampleVariableRateFile(
             generateSampleRateFile.getValue());
        return ResultCode.SUCCESS;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_ACCT_CANNOT_GENERATE_SAMPLE_RATE_FILE.get(
                  generateSampleRateFile.getValue().getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // If we need to create a fixed-rate barrier and/or use a variable rate
    // definition, then set that up.
    final IntegerArgument ratePerSecond =
         parser.getIntegerArgument(ARG_RATE_PER_SECOND);
    final FileArgument variableRateData =
         parser.getFileArgument(ARG_VARIABLE_RATE_DATA);
    if (ratePerSecond.isPresent() || variableRateData.isPresent())
    {
      if (ratePerSecond.isPresent())
      {
        rateLimiter = new FixedRateBarrier(1000L, ratePerSecond.getValue());
      }
      else
      {
        rateLimiter = new FixedRateBarrier(1000L, Integer.MAX_VALUE);
      }

      if (variableRateData.isPresent())
      {
        try
        {
          rateAdjustor = RateAdjustor.newInstance(rateLimiter,
               ratePerSecond.getValue(), variableRateData.getValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_ACCT_CANNOT_CREATE_RATE_ADJUSTOR.get(
                    variableRateData.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.PARAM_ERROR;
        }
      }
    }


    // Create the connection pool to use for all processing.
    final LDAPConnectionPool pool;
    final int numSearchThreads =
         parser.getIntegerArgument(ARG_NUM_SEARCH_THREADS).getValue();
    try
    {
      final int numOperationThreads =
           parser.getIntegerArgument(ARG_NUM_THREADS).getValue();
      pool = getConnectionPool(numOperationThreads,
           (numOperationThreads + numSearchThreads));

      // Explicitly disable automatic retry, since it probably won't work
      // reliably for extended operations anyway.  We'll handle retry manually.
      pool.setRetryFailedOperationsDueToInvalidConnections(false);

      // Set a maximum connection age of 30 minutes.
      pool.setMaxConnectionAgeMillis(1_800_000L);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      wrapErr(0, WRAP_COLUMN,
           ERR_MANAGE_ACCT_CANNOT_CREATE_CONNECTION_POOL.get(getToolName(),
                le.getMessage()));
      return le.getResultCode();
    }


    try
    {
      // Create the output writer.  This should always succeed.
      outputWriter = new LDIFWriter(getOut());



      // Create the reject writer if appropriate.
      final FileArgument rejectFile = parser.getFileArgument(ARG_REJECT_FILE);
      if (rejectFile.isPresent())
      {
        final BooleanArgument appendToRejectFile =
             parser.getBooleanArgument(ARG_APPEND_TO_REJECT_FILE);

        try
        {
          rejectWriter = new LDIFWriter(new FileOutputStream(
               rejectFile.getValue(), appendToRejectFile.isPresent()));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN,
               ERR_MANAGE_ACCT_CANNOT_CREATE_REJECT_WRITER.get(
                    rejectFile.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }
      }


      // Create the processor that will be used to actually perform the
      // manage-account operation processing for each entry.
      final ManageAccountProcessor processor;
      try
      {
        processor = new ManageAccountProcessor(this, pool, rateLimiter,
             outputWriter, rejectWriter);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        wrapErr(0, WRAP_COLUMN,
             ERR_MANAGE_ACCT_CANNOT_CREATE_PROCESSOR.get(
                  StaticUtils.getExceptionMessage(le)));
        return le.getResultCode();
      }


      // If we should use a rate adjustor, then start it now.
      if (rateAdjustor != null)
      {
        rateAdjustor.start();
      }


      // If any targetDN values were provided, then process them now.
      final DNArgument targetDN = parser.getDNArgument(ARG_TARGET_DN);
      if (targetDN.isPresent())
      {
        for (final DN dn : targetDN.getValues())
        {
          if (cancelRequested())
          {
            return ResultCode.USER_CANCELED;
          }

          processor.process(dn.toString());
        }
      }


      // If any DN input files were specified, then process them now.
      final FileArgument dnInputFile =
           parser.getFileArgument(ARG_DN_INPUT_FILE);
      if (dnInputFile.isPresent())
      {
        for (final File f : dnInputFile.getValues())
        {
          DNFileReader reader = null;
          try
          {
            reader = new DNFileReader(f);
            while (true)
            {
              if (cancelRequested())
              {
                return ResultCode.USER_CANCELED;
              }

              final DN dn;
              try
              {
                dn = reader.readDN();
              }
              catch (final LDAPException le)
              {
                Debug.debugException(le);
                processor.handleMessage(le.getMessage(), true);
                continue;
              }

              if (dn == null)
              {
                break;
              }

              processor.process(dn.toString());
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            processor.handleMessage(
                 ERR_MANAGE_ACCT_ERROR_READING_DN_FILE.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 true);
          }
          finally
          {
            if (reader != null)
            {
              try
              {
                reader.close();
              }
              catch (final Exception e2)
              {
                Debug.debugException(e2);
              }
            }
          }
        }
      }


      // If any target filters were specified, then process them now.
      final FilterArgument targetFilter =
           parser.getFilterArgument(ARG_TARGET_FILTER);
      if (targetFilter.isPresent())
      {
        searchProcessor =
             new ManageAccountSearchProcessor(this, processor, pool);
        for (final Filter f : targetFilter.getValues())
        {
          searchProcessor.processFilter(f);
        }
      }


      // If any filter input files were specified, then process them now.
      final FileArgument filterInputFile =
           parser.getFileArgument(ARG_FILTER_INPUT_FILE);
      if (filterInputFile.isPresent())
      {
        if (searchProcessor == null)
        {
          searchProcessor =
               new ManageAccountSearchProcessor(this, processor, pool);
        }

        for (final File f : filterInputFile.getValues())
        {
          FilterFileReader reader = null;
          try
          {
            reader = new FilterFileReader(f);
            while (true)
            {
              if (cancelRequested())
              {
                return ResultCode.USER_CANCELED;
              }

              final Filter filter;
              try
              {
                filter = reader.readFilter();
              }
              catch (final LDAPException le)
              {
                Debug.debugException(le);
                processor.handleMessage(le.getMessage(), true);
                continue;
              }

              if (filter == null)
              {
                break;
              }

              searchProcessor.processFilter(filter);
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            processor.handleMessage(
                 ERR_MANAGE_ACCT_ERROR_READING_FILTER_FILE.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 true);
          }
          finally
          {
            if (reader != null)
            {
              try
              {
                reader.close();
              }
              catch (final Exception e2)
              {
                Debug.debugException(e2);
              }
            }
          }
        }
      }


      // If any target user IDs were specified, then process them now.
      final StringArgument targetUserID =
           parser.getStringArgument(ARG_TARGET_USER_ID);
      if (targetUserID.isPresent())
      {
        if (searchProcessor == null)
        {
          searchProcessor =
               new ManageAccountSearchProcessor(this, processor, pool);
        }

        for (final String userID : targetUserID.getValues())
        {
          searchProcessor.processUserID(userID);
        }
      }


      // If any user ID input files were specified, then process them now.
      final FileArgument userIDInputFile =
           parser.getFileArgument(ARG_USER_ID_INPUT_FILE);
      if (userIDInputFile.isPresent())
      {
        if (searchProcessor == null)
        {
          searchProcessor =
               new ManageAccountSearchProcessor(this, processor, pool);
        }

        for (final File f : userIDInputFile.getValues())
        {
          BufferedReader reader = null;
          try
          {
            reader = new BufferedReader(new FileReader(f));
            while (true)
            {
              if (cancelRequested())
              {
                return ResultCode.USER_CANCELED;
              }

              final String line = reader.readLine();
              if (line == null)
              {
                break;
              }

              if ((line.length() == 0) || line.startsWith("#"))
              {
                continue;
              }

              searchProcessor.processUserID(line.trim());
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            processor.handleMessage(
                 ERR_MANAGE_ACCT_ERROR_READING_USER_ID_FILE.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 true);
          }
          finally
          {
            if (reader != null)
            {
              try
              {
                reader.close();
              }
              catch (final Exception e2)
              {
                Debug.debugException(e2);
              }
            }
          }
        }
      }


      allFiltersProvided.set(true);
      if (searchProcessor != null)
      {
        searchProcessor.waitForCompletion();
      }

      allDNsProvided.set(true);
      processor.waitForCompletion();
    }
    finally
    {
      pool.close();

      if (rejectWriter != null)
      {
        try
        {
          rejectWriter.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }


    // If we've gotten here, then we can consider the command successful, even
    // if some of the operations failed.
    return ResultCode.SUCCESS;
  }



  /**
   * Retrieves the argument parser for this tool.
   *
   * @return  The argument parser for this tool.
   */
  @Nullable()
  ArgumentParser getArgumentParser()
  {
    return parser;
  }



  /**
   * Indicates whether the tool should cancel its processing.
   *
   * @return  {@code true} if the tool should cancel its processing, or
   *          {@code false} if not.
   */
  boolean cancelRequested()
  {
    return cancelRequested.get();
  }



  /**
   * Indicates whether the manage-account processor has been provided with all
   * of the DNs of all of the entries to process.
   *
   * @return  {@code true} if the manage-account processor has been provided
   *          with all of the DNs of all of the entries to process, or
   *          {@code false} if not.
   */
  boolean allDNsProvided()
  {
    return allDNsProvided.get();
  }



  /**
   * Indicates whether the manage-account search processor has been provided
   * with all of the filters to use to identify entries to process.
   *
   * @return  {@code true} if the manage-account search processor has been
   *          provided with all of the filters to use to identify entries to
   *          process, or {@code false} if not.
   */
  boolean allFiltersProvided()
  {
    return allFiltersProvided.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean registerShutdownHook()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void doShutdownHookProcessing(
                      @Nullable final ResultCode resultCode)
  {
    cancelRequested.set(true);

    if (rateLimiter != null)
    {
      rateLimiter.shutdownRequested();
    }

    if (searchProcessor != null)
    {
      searchProcessor.cancelSearches();
    }
  }



  /**
   * Performs any processing that may be necessary in response to the provided
   * unsolicited notification that has been received from the server.
   *
   * @param connection   The connection on which the unsolicited notification
   *                     was received.
   * @param notification The unsolicited notification that has been received
   *                     from the server.
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    final String message = INFO_MANAGE_ACCT_UNSOLICITED_NOTIFICATION.get(
         String.valueOf(connection), String.valueOf(notification));
    if (outputWriter == null)
    {
      err();
      err("* " + message);
      err();
    }
    else
    {
      try
      {
        outputWriter.writeComment(message, true, true);
        outputWriter.flush();
      }
      catch (final Exception e)
      {
        // We can't really do anything about this.
        Debug.debugException(e);
      }
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

    createSubCommandExample(examples,
         ManageAccountSubCommandType.GET_ALL,
         INFO_MANAGE_ACCT_SC_GET_ALL_EXAMPLE.get(EXAMPLE_TARGET_USER_DN));

    createSubCommandExample(examples,
         ManageAccountSubCommandType.GET_ACCOUNT_USABILITY_ERRORS,
         INFO_MANAGE_ACCT_SC_GET_USABILITY_ERRORS_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));

    createSubCommandExample(examples,
         ManageAccountSubCommandType.SET_ACCOUNT_IS_DISABLED,
         INFO_MANAGE_ACCT_SC_SET_IS_DISABLED_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN),
         "--accountIsDisabled", "true");

    createSubCommandExample(examples,
         ManageAccountSubCommandType.CLEAR_AUTHENTICATION_FAILURE_TIMES,
         INFO_MANAGE_ACCT_SC_CLEAR_AUTH_FAILURE_TIMES_EXAMPLE.get(
              EXAMPLE_TARGET_USER_DN));

    return examples;
  }
}
