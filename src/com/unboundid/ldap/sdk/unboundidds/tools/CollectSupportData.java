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



import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.controls.NoOpRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataExtendedRequestProperties;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DurationCollectSupportDataLogCaptureWindow;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            HeadAndTailSizeCollectSupportDataLogCaptureWindow;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionPostConnectProcessor;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            TimeWindowCollectSupportDataLogCaptureWindow;
import com.unboundid.ldap.sdk.unboundidds.tasks.CollectSupportDataSecurityLevel;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.TimestampArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that may be used to invoke the
 * collect-support-data utility in the Ping Identity Directory Server and
 * related server products.
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
 * Note that this is a client-side wrapper for the application.  While it may
 * be used to invoke the tool against a remote server using the
 * {@link CollectSupportDataExtendedRequest}, it does not include direct support
 * for invoking the tool against a local instance.  That will be accomplished
 * indirectly by invoking the server-side version of the tool via reflection.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CollectSupportData
       extends LDAPCommandLineTool
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The Ping Identity Directory Server's default access log timestamp format
   * when configured to use millisecond precision.
   */
  @NotNull static final String SERVER_LOG_TIMESTAMP_FORMAT_WITH_MILLIS =
       "'['dd/MMM/yyyy:HH:mm:ss.SSS Z']'";



  /**
   * The Ping Identity Directory Server's default access log timestamp format
   * when configured to use second precision.
   */
  @NotNull static final String SERVER_LOG_TIMESTAMP_FORMAT_WITHOUT_MILLIS =
       "'['dd/MMM/yyyy:HH:mm:ss Z']'";



  /**
   * The fully-qualified name of the class in the server codebase that will be
   * invoked to perform collect-support-data processing when the
   * --useRemoteServer argument is not provided.
   */
  @NotNull private static final String SERVER_CSD_TOOL_CLASS =
       "com.unboundid.directory.server.tools.CollectSupportData";



  // The completion message for this tool, if available.
  @NotNull private final AtomicReference<String> toolCompletionMessage;

  // The command-line arguments supported by this tool.
  @Nullable private ArgumentParser parser;
  @Nullable private BooleanArgument archiveExtensionSourceArg;
  @Nullable private BooleanArgument collectExpensiveDataArg;
  @Nullable private BooleanArgument collectReplicationStateDumpArg;
  @Nullable private BooleanArgument dryRunArg;
  @Nullable private BooleanArgument encryptArg;
  @Nullable private BooleanArgument generatePassphraseArg;
  @Nullable private BooleanArgument includeBinaryFilesArg;
  @Nullable private BooleanArgument noLDAPArg;
  @Nullable private BooleanArgument noPromptArg;
  @Nullable private BooleanArgument scriptFriendlyArg;
  @Nullable private BooleanArgument sequentialArg;
  @Nullable private BooleanArgument useAdministrativeSessionArg;
  @Nullable private BooleanArgument useRemoteServerArg;
  @Nullable private DurationArgument logDurationArg;
  @Nullable private FileArgument decryptArg;
  @Nullable private FileArgument outputPathArg;
  @Nullable private FileArgument passphraseFileArg;
  @Nullable private IntegerArgument jstackCountArg;
  @Nullable private IntegerArgument logFileHeadCollectionSizeKBArg;
  @Nullable private IntegerArgument logFileTailCollectionSizeKBArg;
  @Nullable private IntegerArgument reportCountArg;
  @Nullable private IntegerArgument reportIntervalSecondsArg;
  @Nullable private IntegerArgument pidArg;
  @Nullable private IntegerArgument proxyToServerPortArg;
  @Nullable private StringArgument commentArg;
  @Nullable private StringArgument proxyToServerAddressArg;
  @Nullable private StringArgument securityLevelArg;
  @Nullable private StringArgument logTimeRangeArg;



  /**
   * Invokes this tool with the provided set of command-line arguments.  The
   * JVM's default standard output and standard error streams will be used.
   *
   * @param  args  The set of command-line arguments provided to this program.
   *               It must not be {@code null} but may be empty.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if ((resultCode != ResultCode.SUCCESS) &&
         (resultCode != ResultCode.NO_OPERATION))
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
   * @param  args  The set of command-line arguments provided to this program.
   *               It must not be {@code null} but may be empty.
   *
   * @return  A result code indicating the final status of the processing that
   *          was performed.  A result code of {@link ResultCode#SUCCESS}
   *          indicates that all processing was successful.  A result code of
   *          {@link ResultCode#NO_OPERATION} indicates that it is likely that
   *          processing would have been successful if the --dryRun argument
   *          had not been provided.  Any other result code indicates that the
   *          processing did not complete successfully.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final CollectSupportData tool = new CollectSupportData(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool that will use the provided streams for
   * standard output and standard error.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public CollectSupportData(@Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    super(out, err);

    toolCompletionMessage = new AtomicReference<>();

    parser = null;
    archiveExtensionSourceArg = null;
    collectExpensiveDataArg = null;
    collectReplicationStateDumpArg = null;
    dryRunArg = null;
    encryptArg = null;
    generatePassphraseArg = null;
    includeBinaryFilesArg = null;
    noLDAPArg = null;
    noPromptArg = null;
    scriptFriendlyArg = null;
    sequentialArg = null;
    useRemoteServerArg = null;
    logDurationArg = null;
    logFileHeadCollectionSizeKBArg = null;
    logFileTailCollectionSizeKBArg = null;
    jstackCountArg = null;
    outputPathArg = null;
    reportCountArg = null;
    decryptArg = null;
    passphraseFileArg = null;
    reportIntervalSecondsArg = null;
    pidArg = null;
    proxyToServerPortArg = null;
    commentArg = null;
    logTimeRangeArg = null;
    proxyToServerAddressArg = null;
    securityLevelArg = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "collect-support-data";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_CSD_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.singletonList(INFO_CSD_TOOL_DESCRIPTION_2.get());
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
    return false;
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
    if ((noPromptArg != null) && noPromptArg.isPresent())
    {
      return false;
    }

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
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return toolCompletionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;

    // Output-related arguments.
    outputPathArg = new FileArgument(null, "outputPath", false, 1, null,
         INFO_CSD_ARG_DESC_OUTPUT_PATH.get(), false, true, false, false);
    outputPathArg.addLongIdentifier("output-path", true);
    outputPathArg.addLongIdentifier("outputFile", true);
    outputPathArg.addLongIdentifier("output-file", true);
    outputPathArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_OUTPUT.get());
    parser.addArgument(outputPathArg);

    encryptArg = new BooleanArgument(null, "encrypt", 1,
         INFO_CSD_ARG_DESC_ENCRYPT.get());
    encryptArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_OUTPUT.get());
    parser.addArgument(encryptArg);

    passphraseFileArg = new FileArgument(null, "passphraseFile", false, 1,
         null, INFO_CSD_ARG_DESC_PASSPHRASE_FILE.get(), false, true, true,
         false);
    passphraseFileArg.addLongIdentifier("passphrase-file", true);
    passphraseFileArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_OUTPUT.get());
    parser.addArgument(passphraseFileArg);

    generatePassphraseArg = new BooleanArgument(null, "generatePassphrase", 1,
         INFO_CSD_ARG_DESC_GENERATE_PASSPHRASE.get());
    generatePassphraseArg.addLongIdentifier("generate-passphrase", true);
    generatePassphraseArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_OUTPUT.get());
    parser.addArgument(generatePassphraseArg);

    decryptArg = new FileArgument(null, "decrypt", false, 1, null,
         INFO_CSD_ARG_DESC_DECRYPT.get(), false, true, true, false);
    decryptArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_OUTPUT.get());
    parser.addArgument(decryptArg);


    // Collection-related arguments.
    collectExpensiveDataArg = new BooleanArgument(null, "collectExpensiveData",
         1, INFO_CSD_ARG_DESC_COLLECT_EXPENSIVE_DATA.get());
    collectExpensiveDataArg.addLongIdentifier("collect-expensive-data", true);
    collectExpensiveDataArg.addLongIdentifier("includeExpensiveData", true);
    collectExpensiveDataArg.addLongIdentifier("include-expensive-data", true);
    collectExpensiveDataArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(collectExpensiveDataArg);

    collectReplicationStateDumpArg = new BooleanArgument(null,
         "collectReplicationStateDump", 1,
         INFO_CSD_ARG_DESC_COLLECT_REPL_STATE.get());
    collectReplicationStateDumpArg.addLongIdentifier(
         "collect-replication-state-dump", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "collectReplicationState", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "collect-replication-state", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "includeReplicationStateDump", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "include-replication-state-dump", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "includeReplicationState", true);
    collectReplicationStateDumpArg.addLongIdentifier(
         "include-replication-state", true);
    collectReplicationStateDumpArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(collectReplicationStateDumpArg);

    includeBinaryFilesArg = new BooleanArgument(null, "includeBinaryFiles", 1,
         INFO_CSD_ARG_DESC_INCLUDE_BINARY_FILES.get());
    includeBinaryFilesArg.addLongIdentifier("include-binary-files", true);
    includeBinaryFilesArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(includeBinaryFilesArg);

    archiveExtensionSourceArg = new BooleanArgument(null,
         "archiveExtensionSource", 1,
         INFO_CSD_ARG_DESC_ARCHIVE_EXTENSION_SOURCE.get());
    archiveExtensionSourceArg.addLongIdentifier("archive-extension-source",
         true);
    archiveExtensionSourceArg.addLongIdentifier("includeExtensionSource", true);
    archiveExtensionSourceArg.addLongIdentifier("include-extension-source",
         true);
    archiveExtensionSourceArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(archiveExtensionSourceArg);

    sequentialArg = new BooleanArgument(null, "sequential", 1,
         INFO_CSD_ARG_DESC_SEQUENTIAL.get());
    sequentialArg.addLongIdentifier("sequentialMode", true);
    sequentialArg.addLongIdentifier("sequential-mode", true);
    sequentialArg.addLongIdentifier("useSequentialMode", true);
    sequentialArg.addLongIdentifier("use-sequential-mode", true);
    sequentialArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(sequentialArg);

    securityLevelArg = new StringArgument(null, "securityLevel", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_SECURITY_LEVEL.get(),
         INFO_CSD_ARG_DESC_SECURITY_LEVEL.get(),
         StaticUtils.setOf(
              CollectSupportDataSecurityLevel.NONE.getName(),
              CollectSupportDataSecurityLevel.OBSCURE_SECRETS.getName(),
              CollectSupportDataSecurityLevel.MAXIMUM.getName()));
    securityLevelArg.addLongIdentifier("security-level", true);
    securityLevelArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(securityLevelArg);

    jstackCountArg = new IntegerArgument(null, "jstackCount", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_COUNT.get(),
         INFO_CSD_ARG_DESC_JSTACK_COUNT.get(), 0, Integer.MAX_VALUE);
    jstackCountArg.addLongIdentifier("jstack-count", true);
    jstackCountArg.addLongIdentifier("maxJstacks", true);
    jstackCountArg.addLongIdentifier("max-jstacks", true);
    jstackCountArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(jstackCountArg);

    reportCountArg = new IntegerArgument(null, "reportCount", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_COUNT.get(),
         INFO_CSD_ARG_DESC_REPORT_COUNT.get(), 0, Integer.MAX_VALUE);
    reportCountArg.addLongIdentifier("report-count", true);
    reportCountArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(reportCountArg);

    reportIntervalSecondsArg = new IntegerArgument(null,
         "reportIntervalSeconds", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_SECONDS.get(),
         INFO_CSD_ARG_DESC_REPORT_INTERVAL_SECONDS.get(), 1,
         Integer.MAX_VALUE);
    reportIntervalSecondsArg.addLongIdentifier("report-interval-seconds", true);
    reportIntervalSecondsArg.addLongIdentifier("reportInterval", true);
    reportIntervalSecondsArg.addLongIdentifier("report-interval", true);
    reportIntervalSecondsArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(reportIntervalSecondsArg);

    logTimeRangeArg = new StringArgument(null, "logTimeRange", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_TIME_RANGE.get(),
         INFO_CSD_ARG_DESC_TIME_RANGE.get());
    logTimeRangeArg.addLongIdentifier("log-time-range", true);
    logTimeRangeArg.addLongIdentifier("timeRange", true);
    logTimeRangeArg.addLongIdentifier("time-range", true);
    logTimeRangeArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(logTimeRangeArg);

    logDurationArg = new DurationArgument(null, "logDuration", false, null,
         INFO_CSD_ARG_DESC_DURATION.get());
    logDurationArg.addLongIdentifier("log-duration", true);
    logDurationArg.addLongIdentifier("duration", true);
    logDurationArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(logDurationArg);

    logFileHeadCollectionSizeKBArg = new IntegerArgument(null,
         "logFileHeadCollectionSizeKB", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_SIZE_KB.get(),
         INFO_CSD_ARG_DESC_LOG_HEAD_SIZE_KB.get(), 0, Integer.MAX_VALUE);
    logFileHeadCollectionSizeKBArg.addLongIdentifier(
         "log-file-head-collection-size-kb", true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier("logFileHeadSizeKB", true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier("log-file-head-size-kb",
         true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier("logHeadCollectionSizeKB",
         true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier(
         "log-head-collection-size-kb", true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier("logHeadSizeKB", true);
    logFileHeadCollectionSizeKBArg.addLongIdentifier("log-head-size-kb", true);
    logFileHeadCollectionSizeKBArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(logFileHeadCollectionSizeKBArg);

    logFileTailCollectionSizeKBArg = new IntegerArgument(null,
         "logFileTailCollectionSizeKB", false, 1,
         INFO_CSD_ARG_PLACEHOLDER_SIZE_KB.get(),
         INFO_CSD_ARG_DESC_LOG_TAIL_SIZE_KB.get(), 0, Integer.MAX_VALUE);
    logFileTailCollectionSizeKBArg.addLongIdentifier(
         "log-file-tail-collection-size-kb", true);
    logFileTailCollectionSizeKBArg.addLongIdentifier("logFileTailSizeKB", true);
    logFileTailCollectionSizeKBArg.addLongIdentifier("log-file-tail-size-kb",
         true);
    logFileTailCollectionSizeKBArg.addLongIdentifier("logTailCollectionSizeKB",
         true);
    logFileTailCollectionSizeKBArg.addLongIdentifier(
         "log-tail-collection-size-kb", true);
    logFileTailCollectionSizeKBArg.addLongIdentifier("logTailSizeKB", true);
    logFileTailCollectionSizeKBArg.addLongIdentifier("log-tail-size-kb", true);
    logFileTailCollectionSizeKBArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(logFileTailCollectionSizeKBArg);

    pidArg = new IntegerArgument(null, "pid", false, 0,
         INFO_CSD_ARG_PLACEHOLDER_PID.get(), INFO_CSD_ARG_DESC_PID.get());
    pidArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(pidArg);

    commentArg = new StringArgument(null, "comment", false, 1, null,
         INFO_CSD_ARG_DESC_COMMENT.get());
    commentArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COLLECTION.get());
    parser.addArgument(commentArg);


    // Communication-related arguments.
    useRemoteServerArg = new BooleanArgument(null, "useRemoteServer", 1,
         INFO_CSD_ARG_DEC_USE_REMOTE_SERVER.get());
    useRemoteServerArg.addLongIdentifier("use-remote-server", true);
    useRemoteServerArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COMMUNICATION.get());
    parser.addArgument(useRemoteServerArg);

    useAdministrativeSessionArg = new BooleanArgument(null,
         "useAdministrativeSession", 1,
         INFO_CSD_ARG_DESC_USE_ADMIN_SESSION.get());
    useAdministrativeSessionArg.addLongIdentifier("use-administrative-session",
         true);
    useAdministrativeSessionArg.addLongIdentifier("useAdminSession", true);
    useAdministrativeSessionArg.addLongIdentifier("use-admin-session",
         true);
    useAdministrativeSessionArg.addLongIdentifier("administrativeSession",
         true);
    useAdministrativeSessionArg.addLongIdentifier("administrative-session",
         true);
    useAdministrativeSessionArg.addLongIdentifier("adminSession", true);
    useAdministrativeSessionArg.addLongIdentifier("admin-session", true);
    useAdministrativeSessionArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COMMUNICATION.get());
    parser.addArgument(useAdministrativeSessionArg);

    proxyToServerAddressArg = new StringArgument(null, "proxyToServerAddress",
         false, 1, INFO_CSD_ARG_PLACEHOLDER_ADDRESS.get(),
         INFO_CSD_ARG_DESC_PROXY_TO_ADDRESS.get());
    proxyToServerAddressArg.addLongIdentifier("proxy-to-server-address", true);
    proxyToServerAddressArg.addLongIdentifier("proxyToAddress", true);
    proxyToServerAddressArg.addLongIdentifier("proxy-to-address", true);
    proxyToServerAddressArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COMMUNICATION.get());
    parser.addArgument(proxyToServerAddressArg);

    proxyToServerPortArg = new IntegerArgument(null, "proxyToServerPort", false,
         1, INFO_CSD_ARG_PLACEHOLDER_PORT.get(),
         INFO_CSD_ARG_DESC_PROXY_TO_PORT.get(), 1, 65535);
    proxyToServerPortArg.addLongIdentifier("proxy-to-server-port", true);
    proxyToServerPortArg.addLongIdentifier("proxyToPort", true);
    proxyToServerPortArg.addLongIdentifier("proxy-to-port", true);
    proxyToServerPortArg.setArgumentGroupName(
         INFO_CSD_ARG_GROUP_COMMUNICATION.get());
    parser.addArgument(proxyToServerPortArg);

    noLDAPArg = new BooleanArgument(null, "noLDAP", 1,
         INFO_CSD_ARG_DESC_NO_LDAP.get());
    noLDAPArg.addLongIdentifier("no-ldap", true);
    noLDAPArg.setArgumentGroupName(INFO_CSD_ARG_GROUP_COMMUNICATION.get());
    parser.addArgument(noLDAPArg);


    // Other arguments.
    noPromptArg = new BooleanArgument('n', "noPrompt",  1,
         INFO_CSD_ARG_DESC_NO_PROMPT.get());
    noPromptArg.addLongIdentifier("no-prompt", true);
    parser.addArgument(noPromptArg);

    dryRunArg = new BooleanArgument(null, "dryRun", 1,
         INFO_CSD_ARG_DESC_DRY_RUN.get());
    dryRunArg.addLongIdentifier("dry-run", true);
    dryRunArg.addLongIdentifier("noOperation", true);
    dryRunArg.addLongIdentifier("no-operation", true);
    dryRunArg.addLongIdentifier("noOp", true);
    dryRunArg.addLongIdentifier("no-op", true);
    parser.addArgument(dryRunArg);

    scriptFriendlyArg = new BooleanArgument(null, "scriptFriendly", 1,
         INFO_CSD_ARG_DESC_SCRIPT_FRIENDLY.get());
    scriptFriendlyArg.addLongIdentifier("script-friendly", true);
    scriptFriendlyArg.setHidden(true);
    parser.addArgument(scriptFriendlyArg);


    // If the --useRemoteServer argument is provided, then none of the --pid,
    // --decrypt, --noLDAP, or --scriptFriendly arguments may be given.
    parser.addExclusiveArgumentSet(useRemoteServerArg, pidArg);
    parser.addExclusiveArgumentSet(useRemoteServerArg, decryptArg);
    parser.addExclusiveArgumentSet(useRemoteServerArg, noLDAPArg);
    parser.addExclusiveArgumentSet(useRemoteServerArg, scriptFriendlyArg);

    // The --useAdministrativeSession argument can only be provided if the
    // --useRemoteServer argument is also given.
    parser.addDependentArgumentSet(useAdministrativeSessionArg,
         useRemoteServerArg);

    // If the --proxyToServerAddress or --proxyToServerPort argument is given,
    // then the other must be provided as well.
    parser.addMutuallyDependentArgumentSet(proxyToServerAddressArg,
         proxyToServerPortArg);

    // The --proxyToServerAddress and --proxyToServerPort arguments can only
    // be used if the --useRemoteServer argument is given.
    parser.addDependentArgumentSet(proxyToServerAddressArg, useRemoteServerArg);
    parser.addDependentArgumentSet(proxyToServerPortArg, useRemoteServerArg);

    // The --logTimeRange and --logDuration arguments cannot be used together.
    parser.addExclusiveArgumentSet(logTimeRangeArg, logDurationArg);

    // Neither the --logFileHeadCollectionSizeKB argument nor the
    // --logFileTailCollectionSizeKB argument can be used in conjunction with
    // either the --logTimeRange or --logDuration argument.
    parser.addExclusiveArgumentSet(logFileHeadCollectionSizeKBArg,
         logTimeRangeArg, logDurationArg);
    parser.addExclusiveArgumentSet(logFileTailCollectionSizeKBArg,
         logTimeRangeArg, logDurationArg);

    // The --generatePassphrase argument can only be used if both the
    // --encrypt and --passphraseFile arguments are provided.
    parser.addDependentArgumentSet(generatePassphraseArg, encryptArg);
    parser.addDependentArgumentSet(generatePassphraseArg, passphraseFileArg);

    // The --encrypt and --decrypt arguments cannot be used together.
    parser.addExclusiveArgumentSet(encryptArg, decryptArg);


    // There are several arguments that the LDAP SDK's LDAP command-line tool
    // framework offers that the server-side version of the framework does not
    // provide.  Those arguments can only be used in conjunction with the
    // --useRemoteServer argument.
    for (final String argumentIdentifier :
         Arrays.asList("promptForBindPassword", "promptForKeyStorePassword",
              "keyStoreFormat", "promptForTrustStorePassword",
              "trustStoreFormat", "enableSSLDebugging", "useSASLExternal"))
    {
      final Argument arg = parser.getNamedArgument(argumentIdentifier);
      parser.addDependentArgumentSet(arg, useRemoteServerArg);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // If the --logTimeRange argument was provided, then make sure we can
    // parse each of the values and that the end time is greater than or equal
    // to the start time.
    if (logTimeRangeArg.isPresent())
    {
      try
      {
        parseTimeRange(logTimeRangeArg.getValue(),
             useRemoteServerArg.isPresent());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        toolCompletionMessage.set(e.getMessage());
        throw new ArgumentException(e.getMessage(), e);
      }
    }


    // If the --passphraseFile argument was provided without the
    // --generatePassphrase argument, then make sure the file exists.
    if (passphraseFileArg.isPresent() && (! generatePassphraseArg.isPresent()))
    {
      final File passphraseFile = passphraseFileArg.getValue();
      if (! passphraseFile.exists())
      {
        final String message =ERR_CSD_PASSPHRASE_FILE_MISSING.get(
             passphraseFile.getAbsolutePath());
        toolCompletionMessage.set(message);
        throw new ArgumentException(message);
      }
    }


    // If either the --encrypt or --decrypt argument is provided in conjunction
    // with the --noPrompt argument, then the --passphraseFile argument must
    // also have been provided.
    if (noPromptArg.isPresent() &&
         (encryptArg.isPresent() || decryptArg.isPresent()) &&
         (! passphraseFileArg.isPresent()))
    {
      final String message = ERR_CSD_NO_PASSPHRASE_WITH_NO_PROMPT.get();
      toolCompletionMessage.set(message);
      throw new ArgumentException(message);
    }
  }



  /**
   * Parses the provided string as a time range.  If both start and end time
   * values are provided, then they must be separated by a comma; otherwise,
   * there must only be a start time value.  Each timestamp must be in either
   * the generalized time format or the Ping Identity Directory Server's default
   * access log format (with or without millisecond precision).
   *
   * @param  timeRangeStr  The string to be parsed as a time range.  It must not
   *                       be {@code null}.
   * @param  strict        Indicates whether to require strict compliance with
   *                       the timestamp format.  This should be {@code true}
   *                       when the useRemoteServer argument was provided, and
   *                       {@code false} otherwise.
   *
   * @return  An object pair in which the first value is the start time for
   *          the range and the second value is the end time for the range.  The
   *          first element will always be non-{@code null}, but the second
   *          element may be {@code null} if the time range did not specify an
   *          end time.  The entire return value may be {@code null} if the
   *          time range string could not be parsed and {@code strict} is
   *          {@code false}.
   *
   * @throws  LDAPException  If a problem is encountered while parsing the
   *                         provided string as a time range, or if the start
   *                         time is greater than the end time.
   */
  @Nullable()
  static ObjectPair<Date,Date> parseTimeRange(
              @NotNull final String timeRangeStr,
              final boolean strict)
         throws LDAPException
  {
    final Date startTime;
    final Date endTime;

    try
    {
      // See if there is a comma to separate the before and after times.  If so,
      // then parse each value separately.  Otherwise, the value will be just
      // the start time and the current time will be used as the end time.
      final int commaPos = timeRangeStr.indexOf(',');
      if (commaPos > 0)
      {
        startTime = parseTimestamp(timeRangeStr.substring(0, commaPos).trim());
        endTime = parseTimestamp(timeRangeStr.substring(commaPos+1).trim());
      }
      else
      {
        startTime = parseTimestamp(timeRangeStr);
        endTime = null;
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);

      // NOTE:  The server-side version of the collect-support-data tool has a
      // not-so-documented feature in which you can provide rotated file names
      // as an alternative to an actual time range.  We can't handle that
      // when operating against a remote server, so we'll require strict
      // timestamp compliance when --useRemoteServer is provided, but we'll just
      // return null and let the argument value be passed through to the
      // server-side code otherwise.
      if (strict)
      {
        throw e;
      }
      else
      {
        return null;
      }
    }

    if ((endTime != null) && (startTime.getTime() > endTime.getTime()))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_CSD_TIME_RANGE_START_GREATER_THAN_END.get());
    }

    return new ObjectPair<>(startTime, endTime);
  }



  /**
   * Parses the provided string as a timestamp value in either the generalized
   * time format or the Ping Identity Directory Server's default access log
   * format (with or without millisecond precision).
   *
   * @param  timestampStr  The timestamp to be parsed.  It must not be
   *                       {@code null}.
   *
   * @return  The {@code Date} created by parsing the timestamp.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a
   *                         valid timestamp.
   */
  @NotNull()
  static Date parseTimestamp(@NotNull final String timestampStr)
         throws LDAPException
  {
    // First, try using the timestamp argument to parse the timestamp.
    try
    {
      return TimestampArgument.parseTimestamp(timestampStr);
    }
    catch (final Exception e)
    {
      Debug.debugException(Level.FINEST, e);
    }


    // Next, try the server's default access log format with millisecond
    // precision.
    try
    {
      final SimpleDateFormat timestampFormatter =
           new SimpleDateFormat(SERVER_LOG_TIMESTAMP_FORMAT_WITH_MILLIS);
      timestampFormatter.setLenient(false);
      return timestampFormatter.parse(timestampStr);
    }
    catch (final Exception e)
    {
      Debug.debugException(Level.FINEST, e);
    }


    // Next, try the server's default access log format with second precision.
    try
    {
      final SimpleDateFormat timestampFormatter =
           new SimpleDateFormat(SERVER_LOG_TIMESTAMP_FORMAT_WITHOUT_MILLIS);
      timestampFormatter.setLenient(false);
      return timestampFormatter.parse(timestampStr);
    }
    catch (final Exception e)
    {
      Debug.debugException(Level.FINEST, e);
    }


    // If we've gotten here, then we could not parse the timestamp.
    throw new LDAPException(ResultCode.PARAM_ERROR,
         ERR_CSD_TIME_RANGE_CANNOT_PARSE_TIMESTAMP.get(timestampStr));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // If the --useRemoteServer argument was provided, then use the extended
    // operation to perform the processing.  Otherwise, use reflection to invoke
    // the server's version of the collect-support-data tool.
    if (useRemoteServerArg.isPresent())
    {
      return doExtendedOperationProcessing();
    }
    else
    {
      return doLocalProcessing();
    }
  }



  /**
   * Performs the collect-support-data processing against a remote server using
   * the extended operation.
   *
   * @return  A result code that indicates the result of the processing.
   */
  @NotNull()
  private ResultCode doExtendedOperationProcessing()
  {
    // Create a connection pool that will be used to communicate with the
    // server.  Use an administrative session if appropriate.
    final StartAdministrativeSessionPostConnectProcessor p;
    if (useAdministrativeSessionArg.isPresent())
    {
      p = new StartAdministrativeSessionPostConnectProcessor(
           new StartAdministrativeSessionExtendedRequest(getToolName(),
                true));
    }
    else
    {
      p = null;
    }

    final LDAPConnectionPool pool;
    try
    {
      pool = getConnectionPool(1, 1, 0, p, null, true,
           new ReportBindResultLDAPConnectionPoolHealthCheck(this, true,
                false));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      wrapErr(0, WRAP_COLUMN, e.getMessage());
      toolCompletionMessage.set(e.getMessage());
      return e.getResultCode();
    }


    try
    {
      // Create the properties to use for the extended request.
      final CollectSupportDataExtendedRequestProperties properties =
           new CollectSupportDataExtendedRequestProperties();

      final File outputPath = outputPathArg.getValue();
      if (outputPath != null)
      {
        if (! (outputPath.exists() && outputPath.isDirectory()))
        {
          properties.setArchiveFileName(outputPath.getName());
        }
      }

      try
      {
        properties.setEncryptionPassphrase(
             getEncryptionPassphraseForExtOpProcessing());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN, e.getMessage());
        toolCompletionMessage.set(e.getMessage());
        return e.getResultCode();
      }


      properties.setIncludeExpensiveData(collectExpensiveDataArg.isPresent());
      properties.setIncludeReplicationStateDump(
           collectReplicationStateDumpArg.isPresent());
      properties.setIncludeBinaryFiles(includeBinaryFilesArg.isPresent());
      properties.setIncludeExtensionSource(
           archiveExtensionSourceArg.isPresent());
      properties.setUseSequentialMode(sequentialArg.isPresent());

      if (securityLevelArg.isPresent())
      {
        properties.setSecurityLevel(CollectSupportDataSecurityLevel.forName(
             securityLevelArg.getValue()));
      }

      if (jstackCountArg.isPresent())
      {
        properties.setJStackCount(jstackCountArg.getValue());
      }

      if (reportCountArg.isPresent())
      {
        properties.setReportCount(reportCountArg.getValue());
      }

      if (reportIntervalSecondsArg.isPresent())
      {
        properties.setReportIntervalSeconds(
             reportIntervalSecondsArg.getValue());
      }

      if (logTimeRangeArg.isPresent())
      {
        try
        {
          final ObjectPair<Date,Date> timeRange =
               parseTimeRange(logTimeRangeArg.getValue(), true);
          properties.setLogCaptureWindow(
               new TimeWindowCollectSupportDataLogCaptureWindow(
                    timeRange.getFirst(), timeRange.getSecond()));
        }
        catch (final LDAPException e)
        {
          // This should never happen because we should have pre-validated the
          // value.  But handle it just in case.
          Debug.debugException(e);
          wrapErr(0, WRAP_COLUMN, e.getMessage());
          toolCompletionMessage.set(e.getMessage());
          return e.getResultCode();
        }
      }
      else if (logDurationArg.isPresent())
      {
        properties.setLogCaptureWindow(
             new DurationCollectSupportDataLogCaptureWindow(
                  logDurationArg.getValue(TimeUnit.MILLISECONDS)));
      }
      else if (logFileHeadCollectionSizeKBArg.isPresent() ||
           logFileTailCollectionSizeKBArg.isPresent())
      {
        properties.setLogCaptureWindow(
             new HeadAndTailSizeCollectSupportDataLogCaptureWindow(
                  logFileHeadCollectionSizeKBArg.getValue(),
                  logFileTailCollectionSizeKBArg.getValue()));
      }

      if (commentArg.isPresent())
      {
        properties.setComment(commentArg.getValue());
      }

      if (proxyToServerAddressArg.isPresent())
      {
        properties.setProxyToServer(proxyToServerAddressArg.getValue(),
             proxyToServerPortArg.getValue());
      }


      // Create the intermediate response listener that will be used to handle
      // output and archive fragment messages.
      ResultCode resultCode = null;
      try (CollectSupportDataIRListener listener =
           new CollectSupportDataIRListener(this, outputPathArg.getValue()))
      {
        // Construct the extended request to send to the server.
        final Control[] controls;
        if (dryRunArg.isPresent())
        {
          controls = new Control[]
          {
            new NoOpRequestControl()
          };
        }
        else
        {
          controls = StaticUtils.NO_CONTROLS;
        }

        final CollectSupportDataExtendedRequest request =
             new CollectSupportDataExtendedRequest(properties, listener,
                  controls);
        request.setResponseTimeoutMillis(0L);


        // Send the request and read the result.
        final CollectSupportDataExtendedResult result;
        try
        {
          result = (CollectSupportDataExtendedResult)
               pool.processExtendedOperation(request);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          final String message = ERR_CSD_ERROR_SENDING_REQUEST.get(
               StaticUtils.getExceptionMessage(e));
          wrapErr(0, WRAP_COLUMN, message);
          toolCompletionMessage.set(message);
          return e.getResultCode();
        }


        resultCode = result.getResultCode();
        final String diagnosticMessage = result.getDiagnosticMessage();
        if (diagnosticMessage != null)
        {
          if ((resultCode == ResultCode.SUCCESS) ||
               (resultCode == ResultCode.NO_OPERATION))
          {
            wrapOut(0, WRAP_COLUMN, diagnosticMessage);
          }
          else
          {
            wrapErr(0, WRAP_COLUMN, diagnosticMessage);
          }

          toolCompletionMessage.set(diagnosticMessage);
        }
        else
        {
          toolCompletionMessage.set(INFO_CSD_COMPLETED_WITH_RESULT_CODE.get(
               String.valueOf(resultCode)));
        }
      }
      catch (final IOException e)
      {
        Debug.debugException(e);

        if (resultCode == ResultCode.SUCCESS)
        {
          resultCode = ResultCode.LOCAL_ERROR;
          toolCompletionMessage.set(e.getMessage());
        }
      }

      return resultCode;
    }
    finally
    {
      pool.close();
    }
  }



  /**
   * Retrieves the passphrase to use to generate the key for encrypting the
   * support data archive.  This method should only be used when the tool
   * processing will be performed using an extended operation.
   *
   * @return  The passphrase to use to generate the key for encrypting the
   *          support data archive.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         obtain the passphrase.
   */
  @Nullable()
  private ASN1OctetString getEncryptionPassphraseForExtOpProcessing()
          throws LDAPException
  {
    if (! encryptArg.isPresent())
    {
      return null;
    }

    if (passphraseFileArg.isPresent())
    {
      final File passphraseFile = passphraseFileArg.getValue();
      if (generatePassphraseArg.isPresent())
      {
        // Generate a passphrase as a base64url-encoded representation of some
        // randomly generated data.
        final SecureRandom random = CryptoHelper.getSecureRandom();
        final byte[] randomBytes = new byte[64];
        random.nextBytes(randomBytes);
        final String passphrase = Base64.urlEncode(randomBytes, false);

        try (PrintWriter writer = new PrintWriter(passphraseFile))
        {
          writer.println(passphrase);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_CSD_CANNOT_WRITE_GENERATED_PASSPHRASE.get(
                    passphraseFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }

        return new ASN1OctetString(passphrase);
      }
      else
      {
        try
        {
          final char[] passphrase =
               getPasswordFileReader().readPassword(passphraseFile);
          return new ASN1OctetString(new String(passphrase));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          ResultCode resultCode = ResultCode.LOCAL_ERROR;
          if (e instanceof LDAPException)
          {
            resultCode = ((LDAPException) e).getResultCode();
          }

          throw new LDAPException(resultCode,
               ERR_CSD_CANNOT_READ_PASSPHRASE.get(
                    passphraseFile.getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }


    // Prompt for the encryption passphrase.
    while (true)
    {
      try
      {
        getOut().print(INFO_CSD_PASSPHRASE_INITIAL_PROMPT.get());
        final byte[] passphraseBytes = PasswordReader.readPassword();

        getOut().print(INFO_CSD_PASSPHRASE_CONFIRM_PROMPT.get());
        final byte[] confirmBytes = PasswordReader.readPassword();
        if (Arrays.equals(passphraseBytes, confirmBytes))
        {
          return new ASN1OctetString(passphraseBytes);
        }
        else
        {
          wrapErr(0, WRAP_COLUMN, ERR_CSD_PASSPHRASE_MISMATCH.get());
          err();
        }
      }
      catch (final Exception e)
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_CSD_PASSPHRASE_PROMPT_READ_ERROR.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Performs the collect-support-data tool using reflection to invoke the
   * server-side version of the tool.
 *
   * @return  A result code that indicates the result of the processing.
     */
  @NotNull()
  private ResultCode doLocalProcessing()
  {
    // Construct the argument list to use when invoking the server-side code.
    // Although this tool supports all of the arguments that the server-side
    // tool provides, the server-side tool does not support all of the arguments
    // that this version offers, nor does it support all of the variants (e.g.,
    // alternate names) for the arguments that do overlap.
    final List<String> argList = new ArrayList<>(20);

    if (outputPathArg.isPresent())
    {
      argList.add("--outputPath");
      argList.add(outputPathArg.getValue().getAbsolutePath());
    }

    if (noLDAPArg.isPresent())
    {
      argList.add("--noLdap");
    }

    if (pidArg.isPresent())
    {
      for (final Integer pid : pidArg.getValues())
      {
        argList.add("--pid");
        argList.add(pid.toString());
      }
    }

    if (sequentialArg.isPresent())
    {
      argList.add("--sequential");
    }

    if (reportCountArg.isPresent())
    {
      argList.add("--reportCount");
      argList.add(reportCountArg.getValue().toString());
    }

    if (reportIntervalSecondsArg.isPresent())
    {
      argList.add("--reportInterval");
      argList.add(reportIntervalSecondsArg.getValue().toString());
    }

    if (jstackCountArg.isPresent())
    {
      argList.add("--maxJstacks");
      argList.add(jstackCountArg.getValue().toString());
    }

    if (collectExpensiveDataArg.isPresent())
    {
      argList.add("--collectExpensiveData");
    }

    if (collectReplicationStateDumpArg.isPresent())
    {
      argList.add("--collectReplicationStateDump");
    }

    if (commentArg.isPresent())
    {
      argList.add("--comment");
      argList.add(commentArg.getValue());
    }

    if (includeBinaryFilesArg.isPresent())
    {
      argList.add("--includeBinaryFiles");
    }

    if (securityLevelArg.isPresent())
    {
      argList.add("--securityLevel");
      argList.add(securityLevelArg.getValue());
    }

    if (encryptArg.isPresent())
    {
      argList.add("--encrypt");
    }

    if (passphraseFileArg.isPresent())
    {
      argList.add("--passphraseFile");
      argList.add(passphraseFileArg.getValue().getAbsolutePath());
    }

    if (generatePassphraseArg.isPresent())
    {
      argList.add("--generatePassphrase");
    }

    if (decryptArg.isPresent())
    {
      argList.add("--decrypt");
      argList.add(decryptArg.getValue().getAbsolutePath());
    }

    if (logTimeRangeArg.isPresent())
    {
      final ObjectPair<Date,Date> timeRange;
      try
      {
        timeRange = parseTimeRange(logTimeRangeArg.getValue(), false);
      }
      catch (final LDAPException e)
      {
        // This should never happen because we should have pre-validated the
        // value.  But handle it just in case.
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN, e.getMessage());
        return e.getResultCode();
      }

      if (timeRange == null)
      {
        // We'll assume that this means the time range was specified using
        // rotated log filenames, which we can't handle in the LDAP SDK code so
        // we'll just pass the argument value through to the server code.
        argList.add("--timeRange");
        argList.add(logTimeRangeArg.getValue());
      }
      else
      {
        final Date startTime = timeRange.getFirst();
        Date endTime = timeRange.getSecond();
        if (endTime == null)
        {
          endTime = new Date(Math.max(System.currentTimeMillis(),
               startTime.getTime()));
        }

        final SimpleDateFormat timestampFormatter =
             new SimpleDateFormat(SERVER_LOG_TIMESTAMP_FORMAT_WITH_MILLIS);
        argList.add("--timeRange");
        argList.add(timestampFormatter.format(startTime) + ',' +
             timestampFormatter.format(endTime));
      }
    }

    if (logDurationArg.isPresent())
    {
      argList.add("--duration");
      argList.add(DurationArgument.nanosToDuration(
           logDurationArg.getValue(TimeUnit.NANOSECONDS)));
    }

    if (logFileHeadCollectionSizeKBArg.isPresent())
    {
      argList.add("--logFileHeadCollectionSizeKB");
      argList.add(String.valueOf(logFileHeadCollectionSizeKBArg.getValue()));
    }

    if (logFileTailCollectionSizeKBArg.isPresent())
    {
      argList.add("--logFileTailCollectionSizeKB");
      argList.add(String.valueOf(logFileTailCollectionSizeKBArg.getValue()));
    }

    if (archiveExtensionSourceArg.isPresent())
    {
      argList.add("--archiveExtensionSource");
    }

    if (noPromptArg.isPresent())
    {
      argList.add("--no-prompt");
    }

    if (scriptFriendlyArg.isPresent())
    {
      argList.add("--script-friendly");
    }


    // We also need to include values for arguments provided by the LDAP
    // command-line tool framework.
    for (final String argumentIdentifier :
         Arrays.asList("hostname", "port", "bindDN", "bindPassword",
              "bindPasswordFile", "useSSL", "useStartTLS", "trustAll",
              "keyStorePath", "keyStorePassword", "keyStorePasswordFile",
              "trustStorePath", "trustStorePassword", "trustStorePasswordFile",
              "certNickname", "saslOption", "propertiesFilePath",
              "noPropertiesFile"))
    {
      final Argument arg = parser.getNamedArgument(argumentIdentifier);
      if (arg.getNumOccurrences() > 0)
      {
        for (final String value : arg.getValueStringRepresentations(false))
        {
          argList.add("--" + argumentIdentifier);
          if (arg.takesValue())
          {
            argList.add(value);
          }
        }
      }
    }


    // If the --dryRun argument was provided, then return without actually
    // invoking the tool.
    if (dryRunArg.isPresent())
    {
      final String message = INFO_CSD_LOCAL_MODE_DRY_RUN.get();
      wrapOut(0, WRAP_COLUMN, message);
      toolCompletionMessage.set(message);
      return ResultCode.NO_OPERATION;
    }


    // Make sure that we have access to the method in the server codebase that
    // we need to invoke local collect-support-data processing.
    final Method doMainMethod;
    try
    {
      final Class<?> csdToolClass = Class.forName(SERVER_CSD_TOOL_CLASS);
      doMainMethod = csdToolClass.getMethod("doMain", Boolean.TYPE,
           OutputStream.class, OutputStream.class, String[].class);
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);
      final String message = ERR_CSD_SERVER_CODE_NOT_AVAILABLE.get();
      wrapErr(0, WRAP_COLUMN, message);
      toolCompletionMessage.set(message);
      return ResultCode.NOT_SUPPORTED;
    }


    // Invoke the doMain method via reflection
    final String[] argArray = new String[argList.size()];
    argList.toArray(argArray);

    try
    {
      final Object doMainMethodReturnValue = doMainMethod.invoke(null,
           true, getOut(), getErr(), argArray);
      final int exitCode = ((Integer) doMainMethodReturnValue).intValue();
      return ResultCode.valueOf(exitCode);
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);
      final String message =
           ERR_CSD_INVOKE_ERROR.get(StaticUtils.getExceptionMessage(t));
      wrapErr(0, WRAP_COLUMN, message);
      toolCompletionMessage.set(message);
      return ResultCode.LOCAL_ERROR;
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
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));

    examples.put(
         new String[]
         {
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--bindPasswordFile", "admin-pw.txt"
         },
         INFO_CSD_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--useRemoteServer",
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--trustStorePath", "config/truststore",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--bindPasswordFile", "admin-pw.txt",
           "--collectExpensiveData",
           "--collectReplicationStateDump",
           "--securityLevel", "maximum",
           "--logDuration", "10 minutes",
           "--encrypt",
           "--passphraseFile", "encryption-passphrase.txt",
           "--generatePassphrase",
           "--outputPath", "csd.zip"
         },
         INFO_CSD_EXAMPLE_2.get());

    examples.put(
         new String[]
         {
           "--decrypt", "support-data-ds-inst1-" +
                StaticUtils.encodeGeneralizedTime(new Date()) +
              "-zip-encrypted",
           "--passphraseFile", "encryption-passphrase.txt"
         },
         INFO_CSD_EXAMPLE_3.get());

    return examples;
  }
}
