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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionPostConnectProcessor;
import com.unboundid.util.Base64;
import com.unboundid.util.DNFileReader;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provide an LDAP command-line tool that may be used to perform
 * compare operations in an LDAP directory server.
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
public final class LDAPCompare
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which output should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The value used to select the CSV output format.
   */
  @NotNull private static final String OUTPUT_FORMAT_CSV = "csv";



  /**
   * The value used to select the JSON output format.
   */
  @NotNull private static final String OUTPUT_FORMAT_JSON = "json";



  /**
   * The value used to select the tab-delimited output format.
   */
  @NotNull private static final String OUTPUT_FORMAT_TAB_DELIMITED =
       "tab-delimited";



  // A reference to the completion message to return for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // A reference to the argument parser for this tool.
  @Nullable private ArgumentParser argumentParser;

  // The supported command-line arguments.
  @Nullable private BooleanArgument authorizationIdentity;
  @Nullable private BooleanArgument continueOnError;
  @Nullable private BooleanArgument dryRun;
  @Nullable private BooleanArgument followReferrals;
  @Nullable private BooleanArgument getUserResourceLimits;
  @Nullable private BooleanArgument manageDsaIT;
  @Nullable private BooleanArgument scriptFriendly;
  @Nullable private BooleanArgument teeOutput;
  @Nullable private BooleanArgument terse;
  @Nullable private BooleanArgument useAdministrativeSession;
  @Nullable private BooleanArgument useCompareResultCodeAsExitCode;
  @Nullable private BooleanArgument usePasswordPolicyControl;
  @Nullable private BooleanArgument verbose;
  @Nullable private ControlArgument bindControl;
  @Nullable private ControlArgument compareControl;
  @Nullable private DNArgument proxyV1As;
  @Nullable private FileArgument assertionFile;
  @Nullable private FileArgument dnFile;
  @Nullable private FileArgument outputFile;
  @Nullable private FilterArgument assertionFilter;
  @Nullable private StringArgument getAuthorizationEntryAttribute;
  @Nullable private StringArgument operationPurpose;
  @Nullable private StringArgument outputFormat;
  @Nullable private StringArgument proxyAs;



  /**
   * Invokes this tool with the provided set of arguments.  The default standard
   * output and error streams will be used.
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
   * Invokes this tool with the provided set of arguments, and using the
   * provided streams for standard output and error.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
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
    final LDAPCompare tool = new LDAPCompare(out, err);
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
  public LDAPCompare(@Nullable final OutputStream out,
                     @Nullable final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();

    argumentParser = null;

    authorizationIdentity = null;
    continueOnError = null;
    dryRun = null;
    followReferrals = null;
    getUserResourceLimits = null;
    manageDsaIT = null;
    scriptFriendly = null;
    teeOutput = null;
    terse = null;
    useAdministrativeSession = null;
    useCompareResultCodeAsExitCode = null;
    usePasswordPolicyControl = null;
    verbose = null;
    bindControl = null;
    compareControl = null;
    proxyV1As = null;
    assertionFile = null;
    dnFile = null;
    outputFile  = null;
    assertionFilter = null;
    getAuthorizationEntryAttribute = null;
    operationPurpose = null;
    outputFormat = null;
    proxyAs = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldapcompare";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_LDAPCOMPARE_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.unmodifiableList(Arrays.asList(
         INFO_LDAPCOMPARE_TOOL_DESCRIPTION_2.get(),
         INFO_LDAPCOMPARE_TOOL_DESCRIPTION_3.get(),
         INFO_LDAPCOMPARE_TOOL_DESCRIPTION_4.get(),
         INFO_LDAPCOMPARE_TOOL_DESCRIPTION_5.get()));
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
    return INFO_LDAPCOMPARE_TRAILING_ARGS_PLACEHOLDER.get();
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
  @NotNull()
  protected List<Control> getBindControls()
  {
    final List<Control> bindControls = new ArrayList<>(10);

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

    return bindControls;
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
  protected boolean supportsSSLDebugging()
  {
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
    return completionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    argumentParser = parser;

    // Compare operation processing arguments.
    dnFile = new FileArgument('f', "dnFile", false, 1, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_DN_FILE.get(), true, true, true,
         false);
    dnFile.addLongIdentifier("dn-file", true);
    dnFile.addLongIdentifier("filename", true);
    dnFile.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(dnFile);

    assertionFile = new FileArgument(null, "assertionFile", false, 1, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_ASSERTION_FILE.get(), true, true,
         true, false);
    assertionFile.addLongIdentifier("assertion-file", true);
    assertionFile.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(assertionFile);

    followReferrals = new BooleanArgument(null, "followReferrals", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_FOLLOW_REFERRALS.get());
    followReferrals.addLongIdentifier("follow-referrals", true);
    followReferrals.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(followReferrals);

    useAdministrativeSession = new BooleanArgument(null,
         "useAdministrativeSession", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_USE_ADMIN_SESSION.get());
    useAdministrativeSession.addLongIdentifier("use-administrative-session",
         true);
    useAdministrativeSession.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(useAdministrativeSession);

    continueOnError = new BooleanArgument('c', "continueOnError", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_CONTINUE_ON_ERROR.get());
    continueOnError.addLongIdentifier("continue-on-error", true);
    continueOnError.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(continueOnError);

    dryRun = new BooleanArgument('n', "dryRun", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_DRY_RUN.get());
    dryRun.addLongIdentifier("dry-run", true);
    dryRun.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(dryRun);


    // Bind control arguments.
    bindControl = new ControlArgument(null, "bindControl", false, 0, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_BIND_CONTROL.get());
    bindControl.addLongIdentifier("bind-control", true);
    bindControl.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_BIND_CONTROLS.get());
    parser.addArgument(bindControl);

    authorizationIdentity = new BooleanArgument('E', "authorizationIdentity", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_AUTHZ_IDENTITY.get());
    authorizationIdentity.addLongIdentifier("authorization-identity", true);
    authorizationIdentity.addLongIdentifier("useAuthorizationIdentity", true);
    authorizationIdentity.addLongIdentifier("use-authorization-identity", true);
    authorizationIdentity.addLongIdentifier("useAuthorizationIdentityControl",
         true);
    authorizationIdentity.addLongIdentifier(
         "use-authorization-identity-control", true);
    authorizationIdentity.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_BIND_CONTROLS.get());
    parser.addArgument(authorizationIdentity);

    usePasswordPolicyControl = new BooleanArgument(null,
         "usePasswordPolicyControl", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_USE_PW_POLICY_CONTROL.get());
    usePasswordPolicyControl.addLongIdentifier("use-password-policy-control",
         true);
    usePasswordPolicyControl.addLongIdentifier("passwordPolicyControl", true);
    usePasswordPolicyControl.addLongIdentifier("password-policy-control", true);
    usePasswordPolicyControl.addLongIdentifier("passwordPolicy", true);
    usePasswordPolicyControl.addLongIdentifier("password-policy", true);
    usePasswordPolicyControl.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_BIND_CONTROLS.get());
    parser.addArgument(usePasswordPolicyControl);

    getAuthorizationEntryAttribute = new StringArgument(null,
         "getAuthorizationEntryAttribute", false, 0,
         INFO_LDAPCOMPARE_ARG_PLACEHOLDER_ATTRIBUTE.get(),
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_GET_AUTHZ_ENTRY_ATTR.get());
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authorization-entry-attribute", true);
    getAuthorizationEntryAttribute.addLongIdentifier("getAuthzEntryAttribute",
         true);
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authz-entry-attribute", true);
    getAuthorizationEntryAttribute.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_BIND_CONTROLS.get());
    parser.addArgument(getAuthorizationEntryAttribute);

    getUserResourceLimits = new BooleanArgument(null, "getUserResourceLimits",
         1, INFO_LDAPCOMPARE_ARG_PLACEHOLDER_GET_USER_RESOURCE_LIMITS.get());
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits", true);
    getUserResourceLimits.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_BIND_CONTROLS.get());
    parser.addArgument(getUserResourceLimits);


    // Compare control arguments.
    compareControl = new ControlArgument('J', "compareControl", false, 0, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_COMPARE_CONTROL.get());
    compareControl.addLongIdentifier("compare-control", true);
    compareControl.addLongIdentifier("control", true);
    compareControl.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(compareControl);

    proxyAs = new StringArgument('Y', "proxyAs", false, 1,
         INFO_LDAPCOMPARE_ARG_PLACEHOLDER_AUTHZ_ID.get(),
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_PROXY_AS.get());
    proxyAs.addLongIdentifier("proxy-as", true);
    proxyAs.addLongIdentifier("proxyV2As", true);
    proxyAs.addLongIdentifier("proxy-v2-as", true);
    proxyAs.addLongIdentifier("proxyV2", true);
    proxyAs.addLongIdentifier("proxy-v2", true);
    proxyAs.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(proxyAs);

    proxyV1As = new DNArgument(null, "proxyV1As", false, 1, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_PROXY_V1_AS.get());
    proxyV1As.addLongIdentifier("proxy-v1-as", true);
    proxyV1As.addLongIdentifier("proxyV1", true);
    proxyV1As.addLongIdentifier("proxy-v1", true);
    proxyV1As.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(proxyV1As);

    manageDsaIT = new BooleanArgument(null, "manageDsaIT", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_MANAGE_DSA_IT.get());
    manageDsaIT.addLongIdentifier("manage-dsa-it", true);
    manageDsaIT.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(manageDsaIT);

    assertionFilter = new FilterArgument(null, "assertionFilter", false, 1,
         null, INFO_LDAPCOMPARE_ARG_DESCRIPTION_ASSERTION_FILTER.get());
    assertionFilter.addLongIdentifier("assertion-filter", true);
    assertionFilter.addLongIdentifier("assertionControlFilter", true);
    assertionFilter.addLongIdentifier("assertion-control-filter", true);
    assertionFilter.addLongIdentifier("useAssertionControl", true);
    assertionFilter.addLongIdentifier("use-assertion-control", true);
    assertionFilter.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(assertionFilter);

    operationPurpose = new StringArgument(null, "operationPurpose", false, 1,
         INFO_LDAPCOMPARE_ARG_PLACEHOLDER_PURPOSE.get(),
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_OPERATION_PURPOSE.get());
    operationPurpose.addLongIdentifier("operation-purpose", true);
    operationPurpose.addLongIdentifier("purpose", true);
    operationPurpose.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_COMPARE_CONTROLS.get());
    parser.addArgument(operationPurpose);


    // Output Arguments.
    outputFile = new FileArgument(null, "outputFile", false, 1, null,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_OUTPUT_FILE.get(), false, true, true,
         false);
    outputFile.addLongIdentifier("output-file", true);
    outputFile.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputFile);

    teeOutput = new BooleanArgument(null, "teeOutput", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_TEE_OUTPUT.get());
    teeOutput.addLongIdentifier("tee-output", true);
    teeOutput.addLongIdentifier("tee", true);
    teeOutput.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(teeOutput);

    outputFormat = new StringArgument(null, "outputFormat", false, 1,
         INFO_LDAPCOMPARE_ARG_PLACEHOLDER_FORMAT.get(),
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_OUTPUT_FORMAT.get(),
         StaticUtils.setOf(
              OUTPUT_FORMAT_TAB_DELIMITED,
              OUTPUT_FORMAT_CSV,
              OUTPUT_FORMAT_JSON),
         OUTPUT_FORMAT_TAB_DELIMITED);
    outputFormat.addLongIdentifier("output-format", true);
    outputFormat.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputFormat);

    scriptFriendly = new BooleanArgument(null, "scriptFriendly", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_SCRIPT_FRIENDLY.get());
    scriptFriendly.addLongIdentifier("script-friendly", true);
    scriptFriendly.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    scriptFriendly.setHidden(true);
    parser.addArgument(scriptFriendly);

    verbose = new BooleanArgument('v', "verbose", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_VERBOSE.get());
    verbose.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(verbose);

    terse = new BooleanArgument(null, "terse", 1,
         INFO_LDAPCOMPARE_ARG_DESCRIPTION_TERSE.get());
    terse.setArgumentGroupName(INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(terse);

    useCompareResultCodeAsExitCode = new BooleanArgument(null,
         "useCompareResultCodeAsExitCode", 1,
         INFO_LDAPCOMPARE_ARG_DESC_USE_COMPARE_RESULT_CODE_AS_EXIT_CODE.get());
    useCompareResultCodeAsExitCode.addLongIdentifier(
         "use-compare-result-code-as-exit-code", true);
    useCompareResultCodeAsExitCode.addLongIdentifier(
         "useCompareResultCode", true);
    useCompareResultCodeAsExitCode.addLongIdentifier(
         "use-compare-result-code", true);
    useCompareResultCodeAsExitCode.setArgumentGroupName(
         INFO_LDAPCOMPARE_ARG_GROUP_OUTPUT.get());
    parser.addArgument(useCompareResultCodeAsExitCode);

    parser.addExclusiveArgumentSet(dnFile, assertionFile);

    parser.addExclusiveArgumentSet(proxyAs, proxyV1As);

    parser.addDependentArgumentSet(teeOutput, outputFile);

    parser.addExclusiveArgumentSet(verbose, terse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    final List<CompareRequest> compareRequests;
    try
    {
      compareRequests = getCompareRequests();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      return e.getResultCode();
    }


    LDAPConnectionPool pool = null;
    try
    {
      // Create a connection pool that will be used to communicate with the
      // directory server.  If we should use an administrative session, then
      // create a connect processor that will be used to start the session
      // before performing the bind.
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

        pool = getConnectionPool(1, 2, 0, p, null, true,
             new ReportBindResultLDAPConnectionPoolHealthCheck(this, true,
                  verbose.isPresent()));
        pool.setRetryFailedOperationsDueToInvalidConnections(true);


        final PrintStream writer;
        if (outputFile.isPresent())
        {
          try
          {
            writer = new PrintStream(outputFile.getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            logCompletionMessage(true,
                 ERR_LDAPCOMPARE_CANNOT_OPEN_OUTPUT_FILE.get(
                      outputFile.getValue().getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)));
            return ResultCode.LOCAL_ERROR;
          }
        }
        else
        {
          writer = null;
        }


        final LDAPCompareOutputHandler outputHandler;
        switch (StaticUtils.toLowerCase(outputFormat.getValue()))
        {
          case OUTPUT_FORMAT_CSV:
            outputHandler = new LDAPCompareCSVOutputHandler();
            break;
          case OUTPUT_FORMAT_JSON:
            outputHandler = new LDAPCompareJSONOutputHandler();
            break;
          case OUTPUT_FORMAT_TAB_DELIMITED:
          default:
            outputHandler = new LDAPCompareTabDelimitedOutputHandler();
            break;
        }

        if (! terse.isPresent())
        {
          for (final String line : outputHandler.getHeaderLines())
          {
            if (writer != null)
            {
              writer.println(line);
            }

            if ((writer == null) || teeOutput.isPresent())
            {
              out(line);
            }
          }
        }


        ResultCode resultCode = null;
        int numTrue = 0;
        int numFalse = 0;
        int numErrors = 0;
        for (final CompareRequest compareRequest : compareRequests)
        {
          LDAPResult compareResult;
          try
          {
            compareResult = pool.compare(compareRequest);
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);
            compareResult = e.toLDAPResult();
          }

          try
          {
            writeResult(writer, outputHandler, compareRequest, compareResult);
          }
          catch (final LDAPException e)
          {
            Debug.debugException(e);
            logCompletionMessage(true, e.getMessage());
            return e.getResultCode();
          }

          final ResultCode compareResultCode = compareResult.getResultCode();
          if (compareResultCode == ResultCode.COMPARE_TRUE)
          {
            numTrue++;
            if (resultCode == null)
            {
              resultCode = ResultCode.COMPARE_TRUE;
            }
          }
          else if (compareResultCode == ResultCode.COMPARE_FALSE)
          {
            numFalse++;
            if (resultCode == null)
            {
              resultCode = ResultCode.COMPARE_FALSE;
            }
          }
          else
          {
            numErrors++;
            if ((resultCode == null) ||
                 (resultCode == ResultCode.COMPARE_TRUE) ||
                 (resultCode == ResultCode.COMPARE_FALSE))
            {
              resultCode = compareResultCode;
            }

            if (! continueOnError.isPresent())
            {
              return resultCode;
            }
          }
        }

        if (resultCode == ResultCode.COMPARE_TRUE)
        {
          if (compareRequests.size() > 1)
          {
            resultCode = ResultCode.SUCCESS;
            logCompletionMessage(false,
                 INFO_LDAPCOMPARE_RESULT_ALL_SUCCEEDED.get(numTrue, numFalse));
          }
          else
          {
            if (! useCompareResultCodeAsExitCode.isPresent())
            {
              resultCode = ResultCode.SUCCESS;
            }

            logCompletionMessage(false,
                 INFO_LDAPCOMPARE_RESULT_COMPARE_MATCHED.get());
          }
        }
        else if (resultCode == ResultCode.COMPARE_FALSE)
        {
          if (compareRequests.size() > 1)
          {
            resultCode = ResultCode.SUCCESS;
            logCompletionMessage(false,
                 INFO_LDAPCOMPARE_RESULT_ALL_SUCCEEDED.get(numTrue, numFalse));
          }
          else
          {
            if (! useCompareResultCodeAsExitCode.isPresent())
            {
              resultCode = ResultCode.SUCCESS;
            }

            logCompletionMessage(false,
                 INFO_LDAPCOMPARE_RESULT_COMPARE_DID_NOT_MATCH.get());
          }
        }
        else
        {
          if (compareRequests.size() > 1)
          {
            logCompletionMessage(true,
                 ERR_LDAPCOMPARE_RESULT_WITH_ERRORS.get(numErrors, numTrue,
                      numFalse));
          }
          else
          {
            logCompletionMessage(true,
                 ERR_LDAPCOMPARE_RESULT_FAILED.get());
          }
        }

        return resultCode;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        // Unable to create the connection pool, which means that either the
        // connection could not be established or the attempt to authenticate
        // the connection failed.  If the bind failed, then the report bind
        // result health check should have already reported the bind failure.
        // If the failure was something else, then display that failure result.
        if (le.getResultCode() != ResultCode.INVALID_CREDENTIALS)
        {
          for (final String line :
               ResultUtils.formatResult(le, true, 0, WRAP_COLUMN))
          {
            err(line);
          }
        }
        return le.getResultCode();
      }
    }
    finally
    {
      if (pool != null)
      {
        pool.close();
      }
    }
  }



  /**
   * Retrieves a list of the compare requests that should be issued.
   *
   * @return  A list of the compare requests that should be issued.
   *
   * @throws  LDAPException  If a problem occurs while obtaining the compare
   *                         requests to process.
   */
  @NotNull()
  private List<CompareRequest> getCompareRequests()
          throws LDAPException
  {
    final List<String> trailingArgs = argumentParser.getTrailingArguments();
    final int numTrailingArgs = trailingArgs.size();

    if (assertionFile.isPresent())
    {
      if (numTrailingArgs != 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAPCOMPARE_TRAILING_ARGS_WITH_ASSERTION_FILE.get(
                  assertionFile.getIdentifierString()));
      }

      return readAssertionFile(getCompareControls());
    }
    else if (dnFile.isPresent())
    {
      if (numTrailingArgs != 1)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAPCOMPARE_INVALID_TRAILING_ARG_COUNT_WITH_DN_FILE.get(
                  dnFile.getIdentifierString()));
      }

      final ObjectPair<String,byte[]> ava =
           parseAttributeValueAssertion(trailingArgs.get(0));
      return readDNFile(ava.getFirst(), ava.getSecond(), getCompareControls());
    }
    else
    {
      if (numTrailingArgs < 2)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAPCOMPARE_INVALID_TRAILING_ARG_COUNT_WITHOUT_FILE.get(
                  dnFile.getIdentifierString(),
                  assertionFile.getIdentifierString()));
      }

      final Iterator<String> trailingArgsIterator = trailingArgs.iterator();
      final ObjectPair<String,byte[]> ava =
           parseAttributeValueAssertion(trailingArgsIterator.next());
      final String attributeName = ava.getFirst();
      final byte[] assertionValue = ava.getSecond();

      final Control[] controls = getCompareControls();

      final List<CompareRequest> requests = new ArrayList<>(numTrailingArgs-1);
      while (trailingArgsIterator.hasNext())
      {
        final String dnString = trailingArgsIterator.next();
        try
        {
          new DN(dnString);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_LDAPCOMPARE_MALFORMED_TRAILING_ARG_DN.get(dnString,
                    e.getMessage()),
               e);
        }

        requests.add(new CompareRequest(dnString, attributeName,
             assertionValue, controls));
      }

      return requests;
    }
  }



  /**
   * Parses the provided string as an attribute value assertion.  It must
   * start with an attribute name or OID, and that must be followed by either a
   * single colon and the string representation of the assertion value, or
   * two colons and the base64-encoded representation of the assertion value.
   *
   * @param  avaString  The string to parse as an attribute value assertion.  It
   *                    must not be {@code null}.
   *
   * @return  An object pair in which the first element is the parsed attribute
   *          name or OID, and the second element is the parsed assertion value.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         attribute value assertion.
   */
  @NotNull()
  private static ObjectPair<String,byte[]> parseAttributeValueAssertion(
                                                @NotNull final String avaString)
          throws LDAPException
  {
    final int colonPos = avaString.indexOf(':');
    if (colonPos < 0)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAPCOMPARE_AVA_NO_COLON.get(avaString));
    }
    else if (colonPos == 0)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAPCOMPARE_AVA_NO_ATTR.get(avaString));
    }

    final String attributeName = avaString.substring(0, colonPos);
    if (colonPos == (avaString.length() - 1))
    {
      // This means that the assertion value is empty.
      return new ObjectPair<>(attributeName, StaticUtils.NO_BYTES);
    }

    if (avaString.charAt(colonPos+1) == ':')
    {
      // This means that the assertion value is base64-encoded.
      try
      {
        final byte[] avaBytes = Base64.decode(avaString.substring(colonPos+2));
        return new ObjectPair<>(attributeName, avaBytes);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAPCOMPARE_AVA_CANNOT_BASE64_DECODE_VALUE.get(avaString,
                  e.getMessage()),
             e);
      }
    }
    else if (avaString.charAt(colonPos+1) == '<')
    {
      // This means that the assertion value should be read from a file.  The
      // path to that file should immediately follow the less-than symbol, and
      // the exact bytes contained in that file (including line breaks) will be
      // used as the assertion value.
      final String path = avaString.substring(colonPos+2);
      final File file = new File(path);
      if (file.exists())
      {
        try
        {
          final byte[] fileBytes = StaticUtils.readFileBytes(file);
          return new ObjectPair<>(attributeName, fileBytes);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDAPCOMPARE_AVA_CANNOT_READ_FILE.get(avaString,
                    file.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAPCOMPARE_AVA_NO_SUCH_FILE.get(avaString,
                  file.getAbsolutePath()));
      }
    }

    return new ObjectPair<>(attributeName,
         StaticUtils.getBytes(avaString.substring(colonPos+1)));
  }



  /**
   * Reads the compare requests to process from the information in the
   * specified assertion file.  Each line of the file must contain the DN of
   * the target entry followed by one or more tab characters and the
   * attribute-value assertion in the form expected by the
   * {@link #parseAttributeValueAssertion} method.  Empty lines and lines that
   * start with the octothorpe (#) character will be ignored.
   *
   * @param  controls  The controls to include in each of the compare requests.
   *                   It must not be {@code null} but may be empty.
   *
   * @return  A list of the compare requests that should be issued.
   *
   * @throws  LDAPException  If a problem is encountered while parsing the
   *                         contents of the assertion file.
   */
  @NotNull()
  private List<CompareRequest> readAssertionFile(
               @NotNull final Control[] controls)
          throws LDAPException
  {
    final File f = assertionFile.getValue();
    try (FileReader fileReader = new FileReader(f);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      int lineNumber = 0;
      final List<CompareRequest> compareRequests = new ArrayList<>();
      while (true)
      {
        // Read the next line from the file.  If it is null, then we've hit the
        // end fo the file.  If the line is empty or starts with an octothorpe,
        // then skip it and read the next line.
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          if (compareRequests.isEmpty())
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_LDAPCOMPARE_ASSERTION_FILE_EMPTY.get(f.getAbsolutePath()));
          }

          return compareRequests;
        }

        lineNumber++;
        if (line.isEmpty() || line.startsWith("#"))
        {
          continue;
        }


        // Find the first tab on the line.  Then, skip over any subsequent
        // tabs to find the assertion value.
        int tabPos = line.indexOf('\t');
        if (tabPos < 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LDAPCOMPARE_ASSERTION_FILE_LINE_MISSING_TAB.get(
                    line, lineNumber, f.getAbsolutePath()));
        }


        final String dn = line.substring(0, tabPos);
        try
        {
          new DN(dn);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LDAPCOMPARE_ASSERTION_FILE_LINE_INVALID_DN.get(
                    line, lineNumber, f.getAbsolutePath(), dn, e.getMessage()),
               e);
        }

        for (int i=(tabPos+1); i < line.length(); i++)
        {
          if (line.charAt(i) == '\t')
          {
            tabPos = i;
          }
        }

        final String avaString = line.substring(tabPos+1);
        if (avaString.isEmpty())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LDAPCOMPARE_ASSERTION_FILE_LINE_MISSING_AVA.get(
                    line, lineNumber, f.getAbsolutePath()));
        }


        final ObjectPair<String,byte[]> ava;
        try
        {
          ava = parseAttributeValueAssertion(avaString);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LDAPCOMPARE_ASSERTION_FILE_CANNOT_PARSE_AVA.get(
                    line, lineNumber, f.getAbsolutePath(), e.getMessage()),
               e);
        }

        compareRequests.add(new CompareRequest(dn, ava.getFirst(),
             ava.getSecond(), controls));
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAPCOMPARE_CANNOT_READ_ASSERTION_FILE.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Reads the DN file to obtain the DNs of the entries to target and creates
   * the list of compare requests to process.  Each line of the file should
   * contain the DN of an entry to process.  Empty lines and lines that start
   * with the octothorpe (#) character will be ignored.
   *
   * @param  attributeName   The name or OID of the attribute to target with
   *                         each of the compare requests.  It must not be
   *                         {@code null} or empty.
   * @param  assertionValue  The assertion value to use for each of the
   *                         compare requests.  It must not be {@code null}.
   * @param  controls        The controls to include in each of the compare
   *                         requests.  It must not be {@code null} but may be
   *                         empty.
   *
   * @return  A list of the compare requests that should be issued.
   *
   * @throws  LDAPException  If a problem is encountered while parsing the
   *                         contents of the assertion file.
   */
  @NotNull()
  private List<CompareRequest> readDNFile(@NotNull final String attributeName,
                                          @NotNull final byte[] assertionValue,
                                          @NotNull final Control[] controls)
          throws LDAPException
  {
    try (DNFileReader dnFileReader = new DNFileReader(dnFile.getValue()))
    {
      final List<CompareRequest> compareRequests = new ArrayList<>();
      while (true)
      {
        final DN dn;
        try
        {
          dn = dnFileReader.readDN();
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR, e.getMessage(), e);
        }

        if (dn == null)
        {
          if (compareRequests.isEmpty())
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_LDAPCOMPARE_DN_FILE_EMPTY.get(
                      dnFile.getValue().getAbsolutePath()));
          }

          return compareRequests;
        }

        compareRequests.add(new CompareRequest(dn, attributeName,
             assertionValue, controls));
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAPCOMPARE_CANNOT_READ_DN_FILE.get(
                dnFile.getValue().getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the controls that should be included in compare requests.
   *
   * @return  The controls that should be included in compare requests, or an
   *          empty array if no controls should be included.
   *
   * @throws  LDAPException  If a problem occurs while trying to create any of
   *                         the controls.
   */
  @NotNull()
  private Control[] getCompareControls()
          throws LDAPException
  {
    final List<Control> controls = new ArrayList<>();

    if (compareControl.isPresent())
    {
      controls.addAll(compareControl.getValues());
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

    if (manageDsaIT.isPresent())
    {
      controls.add(new ManageDsaITRequestControl(false));
    }

    if (assertionFilter.isPresent())
    {
      controls.add(new AssertionRequestControl(assertionFilter.getValue()));
    }

    if (operationPurpose.isPresent())
    {
      controls.add(new OperationPurposeRequestControl(false, getToolName(),
           getToolVersion(),
           LDAPPasswordModify.class.getName() + ".getUpdateControls",
           operationPurpose.getValue()));
    }

    return controls.toArray(StaticUtils.NO_CONTROLS);
  }



  /**
   * Writes information about the compare result.
   *
   * @param  writer         The writer to use to write to the output file.  It
   *                        may be {@code null} if no output file should be
   *                        used.
   * @param  outputHandler  The output handler that should be used to format the
   *                        result information.  It must not be {@code null}.
   * @param  request        The compare request that was processed.  It must not
   *                        be {@code null}.
   * @param  result         The result for the compare operation.  It must not
   *                        be {@code null}.
   *
   * @throws  LDAPException  If a problem occurred while trying to write the
   *                         result.
   */
  private void writeResult(@Nullable final PrintStream writer,
                    @NotNull final LDAPCompareOutputHandler outputHandler,
                    @NotNull final CompareRequest request,
                    @NotNull final LDAPResult result)
          throws LDAPException
  {
    if (shouldWriteResultToStdErr(result))
    {
      err();
      err(INFO_LDAPCOMPARE_RESULT_HEADER.get());
      err(INFO_LDAPCOMPARE_RESULT_HEADER_DN.get(request.getDN()));
      err(INFO_LDAPCOMPARE_RESULT_HEADER_ATTR.get(request.getAttributeName()));
      err(INFO_LDAPCOMPARE_RESULT_HEADER_VALUE.get(
           request.getAssertionValue()));
      for (final String line : ResultUtils.formatResult(result, true, 0,
           WRAP_COLUMN))
      {
        err(line);
      }
    }

    final String message = outputHandler.formatResult(request, result);
    if (writer != null)
    {
      writer.println(message);
    }

    if ((writer == null) || teeOutput.isPresent())
    {
      out(message);
    }
  }



  /**
   * Indicates whether to write information about the provided result to
   * standard error.
   *
   * @param  result  The result for which to make the determination.  It must
   *                 not be {@code mull}.
   *
   * @return  {@code true} if information about the result should be written to
   *          standard error, or {@code false} if not.
   */
  private boolean shouldWriteResultToStdErr(@NotNull final LDAPResult result)
  {
    if (verbose.isPresent())
    {
      return true;
    }

    if (terse.isPresent())
    {
      return false;
    }

    if (result.hasResponseControl())
    {
      return true;
    }

    return ((result.getResultCode() != ResultCode.COMPARE_TRUE) &&
         (result.getResultCode() != ResultCode.COMPARE_FALSE));
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

    if (! terse.isPresent())
    {
      if (isError)
      {
        wrapErr(0, WRAP_COLUMN, message);
      }
      else
      {
        wrapOut(0, WRAP_COLUMN, message);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    if (! terse.isPresent())
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
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "l:Austin",
           "uid=jdoe,ou=People,dc=example,dc=com"
         },
         INFO_LDAPCOMPARE_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--dnFile", "entry-dns.txt",
           "--outputFormat", "csv",
           "--terse",
           "title:manager"
         },
         INFO_LDAPCOMPARE_EXAMPLE_2.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--assertionFile", "compare-assertions.txt",
           "--outputFormat", "json",
           "--outputFile", "compare-assertion-results.json",
           "--verbose"
         },
         INFO_LDAPCOMPARE_EXAMPLE_3.get());

    return examples;
  }
}
