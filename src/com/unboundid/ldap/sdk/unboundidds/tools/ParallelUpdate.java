/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.HardDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            NameWithEntryUUIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordUpdateBehaviorRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordUpdateBehaviorRequestControlProperties;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReplicationRepairRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressOperationalAttributeUpdateRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressReferentialIntegrityUpdatesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SuppressType;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PassphraseEncryptedStreamHeader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that can be used to read change
 * records for add, delete, modify and modify DN operations from an LDIF file,
 * and then apply them in parallel using multiple threads for higher throughput.
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
 * <BR><BR>
 * Changes in the LDIF file to be processed should be ordered such that if there
 * are any dependencies between changes, prerequisite changes come before the
 * changes that depend on them (for example, if one add change record creates a
 * parent entry and another creates a child entry, the add change record that
 * creates the parent entry must come before the one that creates the child
 * entry).  When this tool is preparing to process a change, it will determine
 * whether the new change depends on any other changes that are currently in
 * progress, and if so, will delay processing that change until its dependencies
 * have been satisfied.  If a change does not depend on any other changes that
 * are currently being processed, then it can be processed in parallel with
 * those changes.
 * <BR><BR>
 * The tool will keep track of any changes that fail in a way that indicates
 * they succeed if re-tried later (for example, an attempt to add an entry that
 * fails because its parent does not exist, but its parent may be created later
 * in the set of LDIF changes), and can optionally re-try those changes after
 * processing is complete.  Any changes that are not retried, as well as changes
 * that still fail after the retry attempts, will be written to a rejects file
 * with information about the reason for the failure so that an administrator
 * can take any necessary further action upon them.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ParallelUpdate
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which long lines should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The name of the password update behavior key that may be used to specify
   * whether an update should be treated as a self-change.
   */
  @NotNull private static final String PW_UPDATE_BEHAVIOR_NAME_IS_SELF_CHANGE =
       "is-self-change";



  /**
   * The name of the password update behavior key that may be used to specify
   * whether an update should allow the password to be provided in pre-encoded
   * form.
   */
  @NotNull private static final String
       PW_UPDATE_BEHAVIOR_NAME_ALLOW_PRE_ENCODED_PW =
            "allow-pre-encoded-password";



  /**
   * The name of the password update behavior key that may be used to specify
   * whether the server should skip validation for the password.
   */
  @NotNull private static final String
       PW_UPDATE_BEHAVIOR_NAME_SKIP_PW_VALIDATION = "skip-password-validation";



  /**
   * The name of the password update behavior key that may be used to specify
   * whether the server should ignore the password history when determining
   * whether to accept the new password.
   */
  @NotNull private static final String
       PW_UPDATE_BEHAVIOR_NAME_IGNORE_PW_HISTORY = "ignore-password-history";



  /**
   * The name of the password update behavior key that may be used to specify
   * whether the server should ignore the minimum password age when determining
   * whether to allow the password change.
   */
  @NotNull private static final String
       PW_UPDATE_BEHAVIOR_NAME_IGNORE_MIN_PW_AGE =
            "ignore-minimum-password-age";



  /**
   * The name of the password update behavior key that may be used to specify
   * the password storage scheme that should be used to encode the new password.
   */
  @NotNull private static final String
       PW_UPDATE_BEHAVIOR_NAME_PW_STORAGE_SCHEME = "password-storage-scheme";



  /**
   * The name of the password update behavior key that may be used to specify
   * whether the user must change their password on the next successful
   * authentication.
   */
  @NotNull private static final String PW_UPDATE_BEHAVIOR_NAME_MUST_CHANGE_PW =
       "must-change-password";



  /**
   * The assured replication local level value that indicates that no assurance
   * is needed.
   */
  @NotNull private static final String ASSURED_REPLICATION_LOCAL_LEVEL_NONE =
       "none";



  /**
   * The assured replication local level value that indicates that the response
   * should be delayed until the change has been received by at least one other
   * local server.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER =
            "received-any-server";



  /**
   * The assured replication local level value that indicates that the response
   * should be delayed until the change has been processed by all available
   * local servers.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS =
            "processed-all-servers";



  /**
   * The assured replication remote level value that indicates that no assurance
   * is needed.
   */
  @NotNull private static final String ASSURED_REPLICATION_REMOTE_LEVEL_NONE =
       "none";



  /**
   * The assured replication remote level value that indicates that the response
   * should be delayed until the change has been received by at least one server
   * in at least one remote location.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION =
            "received-any-remote-location";



  /**
   * The assured replication remote level value that indicates that the response
   * should be delayed until the change has been received by at least one server
   * in all remote locations.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS =
            "received-all-remote-locations";



  /**
   * The assured replication remote level value that indicates that the response
   * should be delayed until the change has been processed by all available
   * servers in all remote locations.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS =
            "processed-all-remote-servers";



  /**
   * The suppress operational attribute update value that indicates that updates
   * to the last access time should be suppressed.
   */
  @NotNull private static final String SUPPRESS_OP_ATTR_LAST_ACCESS_TIME =
       "last-access-time";



  /**
   * The suppress operational attribute update value that indicates that updates
   * to the last login time should be suppressed.
   */
  @NotNull private static final String SUPPRESS_OP_ATTR_LAST_LOGIN_TIME =
       "last-login-time";



  /**
   * The suppress operational attribute update value that indicates that updates
   * to the last login IP address should be suppressed.
   */
  @NotNull private static final String SUPPRESS_OP_ATTR_LAST_LOGIN_IP =
       "last-login-ip";



  /**
   * The suppress operational attribute update value that indicates that updates
   * to the lastmod attributes (creatorsName, createTimestamp, modifiersName,
   * modifyTimestamp) should be suppressed.
   */
  @NotNull private static final String SUPPRESS_OP_ATTR_LASTMOD = "lastmod";



  // Indicates whether an error has occurred and that processing should be
  // aborted.
  @NotNull private final AtomicBoolean shouldAbort;

  // Counters used to keep track of statistical information about processing.
  @NotNull private final AtomicLong opsAttempted;
  @NotNull private final AtomicLong opsRejected;
  @NotNull private final AtomicLong opsSucceeded;
  @NotNull private final AtomicLong totalOpDurationMillis;
  private volatile long initialAttempted;
  private volatile long initialSucceeded;

  // Variables pertaining to operations to be retried.
  @NotNull private final AtomicLong retryQueueSize;
  @NotNull private final
       Map<DN,List<ObjectPair<LDIFChangeRecord,LDAPException>>> retryQueue;

  // The result code for the first operation that was rejected, if any.
  @NotNull private final AtomicReference<ResultCode> firstRejectResultCode;

  // The completion message for this tool, if available.
  @NotNull private final AtomicReference<String> completionMessage;

  // The rate limiter for this tool, if any.
  @Nullable private FixedRateBarrier rateLimiter;

  // Writers used to write rejects and log messages.
  @Nullable private LDIFWriter rejectWriter;
  @Nullable private PrintWriter logWriter;

  // Variables used to keep track of data about processing intervals for use in
  // periodic status updates.
  private volatile long lastOpsAttempted;
  private volatile long lastTotalDurationMillis;
  private volatile long lastUpdateTimeMillis;
  private volatile long processingStartTimeMillis;

  // Thread-local date formatters used to format message timestamps.
  @NotNull private final ThreadLocal<SimpleDateFormat> timestampFormatters;

  // The set of command-line arguments for this program.
  @Nullable private BooleanArgument allowUndeleteArg;
  @Nullable private BooleanArgument defaultAddArg;
  @Nullable private BooleanArgument followReferralsArg;
  @Nullable private BooleanArgument hardDeleteArg;
  @Nullable private BooleanArgument ignoreNoUserModificationArg;
  @Nullable private BooleanArgument isCompressedArg;
  @Nullable private BooleanArgument nameWithEntryUUIDArg;
  @Nullable private BooleanArgument neverRetryArg;
  @Nullable private BooleanArgument replicationRepairArg;
  @Nullable private BooleanArgument softDeleteArg;
  @Nullable private BooleanArgument suppressReferentialIntegrityUpdatesArg;
  @Nullable private BooleanArgument useAssuredReplicationArg;
  @Nullable private BooleanArgument useFirstRejectResultCodeAsExitCodeArg;
  @Nullable private BooleanArgument useManageDsaITArg;
  @Nullable private BooleanArgument usePermissiveModifyArg;
  @Nullable private ControlArgument addControlArg;
  @Nullable private ControlArgument bindControlArg;
  @Nullable private ControlArgument deleteControlArg;
  @Nullable private ControlArgument modifyControlArg;
  @Nullable private ControlArgument modifyDNControlArg;
  @Nullable private DNArgument proxyV1AsArg;
  @Nullable private DurationArgument assuredReplicationTimeoutArg;
  @Nullable private FileArgument encryptionPassphraseFileArg;
  @Nullable private FileArgument ldifFileArg;
  @Nullable private FileArgument logFileArg;
  @Nullable private FileArgument rejectFileArg;
  @Nullable private IntegerArgument numThreadsArg;
  @Nullable private IntegerArgument ratePerSecondArg;
  @Nullable private StringArgument assuredReplicationLocalLevelArg;
  @Nullable private StringArgument assuredReplicationRemoteLevelArg;
  @Nullable private StringArgument operationPurposeArg;
  @Nullable private StringArgument passwordUpdateBehaviorArg;
  @Nullable private StringArgument proxyAsArg;
  @Nullable private StringArgument suppressOperationalAttributeUpdatesArg;



  /**
   * Parses the provided set of command-line arguments and then performs the
   * necessary processing.
   *
   * @param  args  The command-line arguments provided to this program.
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
   * Parses the provided set of command-line arguments and then performs the
   * necessary processing.
   *
   * @param  out   The output stream to which standard output should be written.
   *               It may be {@code null} if standard output should be
   *               suppressed.
   * @param  err   The output stream to which standard error should be written.
   *               It may be {@code null} if standard error should be
   *               suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  Zero if all processing completed successfully, or nonzero if an
   *          error occurred.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final ParallelUpdate parallelupdate = new ParallelUpdate(out, err);
    return parallelupdate.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to which standard output should be written.
   *              It may be {@code null} if standard output should be
   *              suppressed.
   * @param  err  The output stream to which standard error should be written.
   *              It may be {@code null} if standard error should be
   *              suppressed.
   */
  public ParallelUpdate(@Nullable final OutputStream out,
                        @Nullable final OutputStream err)
  {
    super(out, err);

    shouldAbort = new AtomicBoolean(false);
    opsAttempted = new AtomicLong(0L);
    opsRejected = new AtomicLong(0L);
    opsSucceeded = new AtomicLong(0L);
    totalOpDurationMillis = new AtomicLong(0L);
    initialAttempted = 0L;
    initialSucceeded = 0L;
    retryQueueSize = new AtomicLong(0L);
    retryQueue = new TreeMap<>();
    firstRejectResultCode = new AtomicReference<>();
    completionMessage = new AtomicReference<>();
    rejectWriter = null;
    logWriter = null;
    lastOpsAttempted = 0L;
    lastTotalDurationMillis = 0L;
    lastUpdateTimeMillis = 0L;
    processingStartTimeMillis = System.currentTimeMillis();
    timestampFormatters = new ThreadLocal<>();
    allowUndeleteArg = null;
    defaultAddArg = null;
    followReferralsArg = null;
    hardDeleteArg = null;
    ignoreNoUserModificationArg = null;
    isCompressedArg = null;
    nameWithEntryUUIDArg = null;
    neverRetryArg = null;
    replicationRepairArg = null;
    softDeleteArg = null;
    suppressReferentialIntegrityUpdatesArg = null;
    useAssuredReplicationArg = null;
    useFirstRejectResultCodeAsExitCodeArg = null;
    useManageDsaITArg = null;
    usePermissiveModifyArg = null;
    addControlArg = null;
    bindControlArg = null;
    deleteControlArg = null;
    modifyControlArg = null;
    modifyDNControlArg = null;
    proxyV1AsArg = null;
    assuredReplicationTimeoutArg = null;
    encryptionPassphraseFileArg = null;
    ldifFileArg = null;
    logFileArg = null;
    rejectFileArg = null;
    numThreadsArg = null;
    ratePerSecondArg = null;
    assuredReplicationLocalLevelArg = null;
    assuredReplicationRemoteLevelArg = null;
    operationPurposeArg = null;
    passwordUpdateBehaviorArg = null;
    proxyAsArg = null;
    suppressOperationalAttributeUpdatesArg = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "parallel-update";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_PARALLEL_UPDATE_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.unmodifiableList(Arrays.asList(
         INFO_PARALLEL_UPDATE_TOOL_DESCRIPTION_2.get(),
         INFO_PARALLEL_UPDATE_TOOL_DESCRIPTION_3.get()));
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
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    ldifFileArg = new FileArgument('l', "ldifFile", true, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_LDIF_FILE.get(), true, true, true,
         false);
    ldifFileArg.addLongIdentifier("ldif-file", true);
    ldifFileArg.addLongIdentifier("inputFile", true);
    ldifFileArg.addLongIdentifier("input-file", true);
    ldifFileArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(ldifFileArg);

    isCompressedArg = new BooleanArgument('c', "isCompressed", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_IS_COMPRESSED.get());
    isCompressedArg.addLongIdentifier("is-compressed", true);
    isCompressedArg.addLongIdentifier("compressed", true);
    isCompressedArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    isCompressedArg.setHidden(true);
    parser.addArgument(isCompressedArg);

    encryptionPassphraseFileArg = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_ENCRYPTION_PASSPHRASE_FILE.get(),
         true, true, true, false);
    encryptionPassphraseFileArg.addLongIdentifier(
         "encryption-passphrase-file", true);
    encryptionPassphraseFileArg.addLongIdentifier(
         "encryptionPasswordFile", true);
    encryptionPassphraseFileArg.addLongIdentifier(
         "encryption-password-file", true);
    encryptionPassphraseFileArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(encryptionPassphraseFileArg);

    rejectFileArg = new FileArgument('R', "rejectFile", true, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_REJECT_FILE.get(), false, true, true,
         false);
    rejectFileArg.addLongIdentifier("reject-file", true);
    rejectFileArg.addLongIdentifier("rejectsFile", true);
    rejectFileArg.addLongIdentifier("rejects-file", true);
    rejectFileArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(rejectFileArg);

    useFirstRejectResultCodeAsExitCodeArg = new BooleanArgument(null,
         "useFirstRejectResultCodeAsExitCode", 1,
         INFO_PARALLEL_UPDATE_USE_FIRST_REJECT_RC.get());
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-first-reject-result-code-as-exit-code", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "useFirstRejectResultCode", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-first-reject-result-code", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "useFirstRejectResult", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-first-reject-result", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "useRejectResultCodeAsExitCode", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-reject-result-code-as-exit-code", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "useRejectResultCode", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-reject-result-code", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "useRejectResult", true);
    useFirstRejectResultCodeAsExitCodeArg.addLongIdentifier(
         "use-reject-result", true);
    useFirstRejectResultCodeAsExitCodeArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(useFirstRejectResultCodeAsExitCodeArg);

    neverRetryArg = new BooleanArgument('r', "neverRetry", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_NEVER_RETRY.get());
    neverRetryArg.addLongIdentifier("never-retry", true);
    neverRetryArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(neverRetryArg);

    logFileArg = new FileArgument('L', "logFile", false, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_LOG_FILE.get(), false, true, true,
         false);
    logFileArg.addLongIdentifier("log-file", true);
    logFileArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(logFileArg);

    defaultAddArg = new BooleanArgument('a', "defaultAdd", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_DEFAULT_ADD.get());
    defaultAddArg.addLongIdentifier("default-add", true);
    defaultAddArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(defaultAddArg);

    followReferralsArg = new BooleanArgument(null, "followReferrals", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_FOLLOW_REFERRALS.get());
    followReferralsArg.addLongIdentifier("follow-referrals", true);
    followReferralsArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(followReferralsArg);

    numThreadsArg = new IntegerArgument('t', "numThreads", true, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_NUM_THREADS.get(), 1, Integer.MAX_VALUE,
         8);
    numThreadsArg.addLongIdentifier("num-threads", true);
    numThreadsArg.addLongIdentifier("threads", true);
    numThreadsArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(numThreadsArg);

    ratePerSecondArg = new IntegerArgument('s', "ratePerSecond", false, 1,
         null, INFO_PARALLEL_UPDATE_ARG_DESC_RATE_PER_SECOND.get(), 1,
         Integer.MAX_VALUE);
    ratePerSecondArg.addLongIdentifier("rate-per-second", true);
    ratePerSecondArg.addLongIdentifier("requestsPerSecond", true);
    ratePerSecondArg.addLongIdentifier("requests-per-second", true);
    ratePerSecondArg.addLongIdentifier("operationsPerSecond", true);
    ratePerSecondArg.addLongIdentifier("operations-per-second", true);
    ratePerSecondArg.addLongIdentifier("opsPerSecond", true);
    ratePerSecondArg.addLongIdentifier("ops-per-second", true);
    ratePerSecondArg.addLongIdentifier("rate", true);
    ratePerSecondArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_PROCESSING.get());
    parser.addArgument(ratePerSecondArg);

    usePermissiveModifyArg = new BooleanArgument('M', "usePermissiveModify", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_USE_PERMISSIVE_MODIFY.get());
    usePermissiveModifyArg.addLongIdentifier("use-permissive-modify", true);
    usePermissiveModifyArg.addLongIdentifier("permissiveModify", true);
    usePermissiveModifyArg.addLongIdentifier("permissive-modify", true);
    usePermissiveModifyArg.addLongIdentifier("permissive", true);
    usePermissiveModifyArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(usePermissiveModifyArg);

    ignoreNoUserModificationArg = new BooleanArgument(null,
         "ignoreNoUserModification", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_IGNORE_NO_USER_MOD.get());
    ignoreNoUserModificationArg.addLongIdentifier("ignore-no-user-modification",
         true);
    ignoreNoUserModificationArg.addLongIdentifier("ignoreNoUserMod", true);
    ignoreNoUserModificationArg.addLongIdentifier("ignore-no-user-mod", true);
    ignoreNoUserModificationArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(ignoreNoUserModificationArg);

    proxyAsArg = new StringArgument('Y', "proxyAs", false, 1,
         INFO_PARALLEL_UPDATE_ARG_PLACEHOLDER_PROXY_AS.get(),
         INFO_PARALLEL_UPDATE_ARG_DESC_PROXY_AS.get());
    proxyAsArg.addLongIdentifier("proxy-as", true);
    proxyAsArg.addLongIdentifier("proxyV2As", true);
    proxyAsArg.addLongIdentifier("proxy-v2-as", true);
    proxyAsArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(proxyAsArg);

    proxyV1AsArg = new DNArgument(null, "proxyV1As", false, 1, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_PROXY_V1_AS.get());
    proxyV1AsArg.addLongIdentifier("proxy-v1-as", true);
    proxyV1AsArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(proxyV1AsArg);

    passwordUpdateBehaviorArg = new StringArgument(null,
         "passwordUpdateBehavior", false, 0,
         INFO_PARALLEL_UPDATE_ARG_PLACEHOLDER_PW_UPDATE_BEHAVIOR.get(),
         INFO_PARALLEL_UPDATE_ARG_DESC_PW_UPDATE_BEHAVIOR.get());
    passwordUpdateBehaviorArg.addLongIdentifier("password-update-behavior",
         true);
    passwordUpdateBehaviorArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(passwordUpdateBehaviorArg);

    operationPurposeArg = new StringArgument(null, "operationPurpose", false, 1,
         INFO_PARALLEL_UPDATE_ARG_PLACEHOLDER_OPERATION_PURPOSE.get(),
         INFO_PARALLEL_UPDATE_ARG_DESC_OPERATION_PURPOSE.get());
    operationPurposeArg.addLongIdentifier("operation-purpose", true);
    operationPurposeArg.addLongIdentifier("purpose", true);
    operationPurposeArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(operationPurposeArg);

    useManageDsaITArg = new BooleanArgument(null, "useManageDsaIT", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_USE_MANAGE_DSA_IT.get());
    useManageDsaITArg.addLongIdentifier("use-manage-dsa-it", true);
    useManageDsaITArg.addLongIdentifier("manageDsaIT", true);
    useManageDsaITArg.addLongIdentifier("manage-dsa-it", true);
    useManageDsaITArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(useManageDsaITArg);

    nameWithEntryUUIDArg = new BooleanArgument(null, "nameWithEntryUUID", 1,
         INFO_LDAPMODIFY_ARG_DESCRIPTION_NAME_WITH_ENTRY_UUID.get());
    nameWithEntryUUIDArg.addLongIdentifier("name-with-entryuuid", true);
    nameWithEntryUUIDArg.addLongIdentifier("name-with-entry-uuid", true);
    nameWithEntryUUIDArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(nameWithEntryUUIDArg);

    softDeleteArg = new BooleanArgument(null, "useSoftDelete", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_SOFT_DELETE.get());
    softDeleteArg.addLongIdentifier("use-soft-delete", true);
    softDeleteArg.addLongIdentifier("softDelete", true);
    softDeleteArg.addLongIdentifier("soft-delete", true);
    softDeleteArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(softDeleteArg);

    hardDeleteArg = new BooleanArgument(null, "useHardDelete", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_HARD_DELETE.get());
    hardDeleteArg.addLongIdentifier("use-hard-delete", true);
    hardDeleteArg.addLongIdentifier("hardDelete", true);
    hardDeleteArg.addLongIdentifier("hard-delete", true);
    hardDeleteArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(hardDeleteArg);

    allowUndeleteArg = new BooleanArgument(null, "allowUndelete", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_ALLOW_UNDELETE.get());
    allowUndeleteArg.addLongIdentifier("allow-undelete", true);
    allowUndeleteArg.addLongIdentifier("undelete", true);
    allowUndeleteArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(allowUndeleteArg);

    useAssuredReplicationArg = new BooleanArgument(null,
         "useAssuredReplication", 1,
         INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION.get());
    useAssuredReplicationArg.addLongIdentifier("use-assured-replication", true);
    useAssuredReplicationArg.addLongIdentifier("assuredReplication", true);
    useAssuredReplicationArg.addLongIdentifier("assured-replication", true);
    useAssuredReplicationArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(useAssuredReplicationArg);

    assuredReplicationLocalLevelArg = new StringArgument(null,
         "assuredReplicationLocalLevel", false, 1,
         INFO_LDAPDELETE_ARG_PLACEHOLDER_ASSURED_REPLICATION_LOCAL_LEVEL.get(),
         INFO_LDAPDELETE_ARG_DESC_ASSURED_REPLICATION_LOCAL_LEVEL.get(),
         StaticUtils.setOf(
              ASSURED_REPLICATION_LOCAL_LEVEL_NONE,
              ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER,
              ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS),
         (String) null);
    assuredReplicationLocalLevelArg.addLongIdentifier(
         "assured-replication-local-level", true);
    assuredReplicationLocalLevelArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(assuredReplicationLocalLevelArg);

    assuredReplicationRemoteLevelArg = new StringArgument(null,
         "assuredReplicationRemoteLevel", false, 1,
         INFO_PARALLEL_UPDATE_ARG_PLACEHOLDER_ASSURED_REPLICATION_REMOTE_LEVEL.
              get(),
         INFO_PARALLEL_UPDATE_ARG_DESC_ASSURED_REPLICATION_REMOTE_LEVEL.get(),
         StaticUtils.setOf(
              ASSURED_REPLICATION_REMOTE_LEVEL_NONE,
              ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION,
              ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS,
              ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS),
         (String) null);
    assuredReplicationRemoteLevelArg.addLongIdentifier(
         "assured-replication-remote-level", true);
    assuredReplicationRemoteLevelArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(assuredReplicationRemoteLevelArg);

    assuredReplicationTimeoutArg = new DurationArgument(null,
         "assuredReplicationTimeout", false, null,
         INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION_TIMEOUT.get());
    assuredReplicationTimeoutArg.addLongIdentifier(
         "assured-replication-timeout", true);
    assuredReplicationTimeoutArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(assuredReplicationTimeoutArg);

    replicationRepairArg = new BooleanArgument(null, "replicationRepair", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_USE_REPLICATION_REPAIR.get());
    replicationRepairArg.addLongIdentifier("replication-repair", true);
    replicationRepairArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(replicationRepairArg);

    suppressOperationalAttributeUpdatesArg = new StringArgument(null,
         "suppressOperationalAttributeUpdates", false, 0,
         INFO_PARALLEL_UPDATE_ARG_PLACEHOLDER_SUPPRESS_OP_ATTR_UPDATES.get(),
         INFO_PARALLEL_UPDATE_ARG_DESC_SUPPRESS_OP_ATTR_UPDATES.get(),
         StaticUtils.setOf(
              SUPPRESS_OP_ATTR_LAST_ACCESS_TIME,
              SUPPRESS_OP_ATTR_LAST_LOGIN_TIME,
              SUPPRESS_OP_ATTR_LAST_LOGIN_IP,
              SUPPRESS_OP_ATTR_LASTMOD),
         (String) null);
    suppressOperationalAttributeUpdatesArg.addLongIdentifier(
         "suppress-operational-attribute-updates", true);
    suppressOperationalAttributeUpdatesArg.addLongIdentifier(
         "suppressOperationalAttributeUpdate", true);
    suppressOperationalAttributeUpdatesArg.addLongIdentifier(
         "suppress-operational-attribute-update", true);
    suppressOperationalAttributeUpdatesArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(suppressOperationalAttributeUpdatesArg);

    suppressReferentialIntegrityUpdatesArg = new BooleanArgument(null,
         "suppressReferentialIntegrityUpdates", 1,
         INFO_PARALLEL_UPDATE_ARG_DESC_SUPPRESS_REFERENTIAL_INTEGRITY_UPDATES.
              get());
    suppressReferentialIntegrityUpdatesArg.addLongIdentifier(
         "suppress-referential-integrity-updates", true);
    suppressReferentialIntegrityUpdatesArg.addLongIdentifier(
         "suppressReferentialIntegrityUpdate", true);
    suppressReferentialIntegrityUpdatesArg.addLongIdentifier(
         "suppress-referential-integrity-update", true);
    suppressReferentialIntegrityUpdatesArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(suppressReferentialIntegrityUpdatesArg);

    addControlArg = new ControlArgument(null, "addControl", false, 0, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_ADD_CONTROL.get());
    addControlArg.addLongIdentifier("add-control", true);
    addControlArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(addControlArg);

    bindControlArg = new ControlArgument(null, "bindControl", false, 0, null,
         INFO_PARALLEL_UPDATE_ARG_DESC_BIND_CONTROL.get());
    bindControlArg.addLongIdentifier("bind-control", true);
    bindControlArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(bindControlArg);

    deleteControlArg = new ControlArgument(null, "deleteControl", false, 0,
         null, INFO_PARALLEL_UPDATE_ARG_DESC_DELETE_CONTROL.get());
    deleteControlArg.addLongIdentifier("delete-control", true);
    deleteControlArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(deleteControlArg);

    modifyControlArg = new ControlArgument(null, "modifyControl", false, 0,
         null, INFO_PARALLEL_UPDATE_ARG_DESC_MODIFY_CONTROL.get());
    modifyControlArg.addLongIdentifier("modify-control", true);
    modifyControlArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(modifyControlArg);

    modifyDNControlArg = new ControlArgument(null, "modifyDNControl", false, 0,
         null, INFO_PARALLEL_UPDATE_ARG_DESC_MODIFY_DN_CONTROL.get());
    modifyDNControlArg.addLongIdentifier("modify-dn-control", true);
    modifyDNControlArg.setArgumentGroupName(
         INFO_PARALLEL_UPDATE_ARG_GROUP_CONTROLS.get());
    parser.addArgument(modifyDNControlArg);

    parser.addExclusiveArgumentSet(followReferralsArg, useManageDsaITArg);

    parser.addExclusiveArgumentSet(proxyAsArg, proxyV1AsArg);

    parser.addExclusiveArgumentSet(softDeleteArg, hardDeleteArg);

    parser.addDependentArgumentSet(assuredReplicationLocalLevelArg,
         useAssuredReplicationArg);
    parser.addDependentArgumentSet(assuredReplicationRemoteLevelArg,
         useAssuredReplicationArg);
    parser.addDependentArgumentSet(assuredReplicationTimeoutArg,
         useAssuredReplicationArg);


    parser.addExclusiveArgumentSet(useAssuredReplicationArg,
         replicationRepairArg);
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
    final List<Control> bindControls = new ArrayList<>();

    if ((bindControlArg != null) && bindControlArg.isPresent())
    {
      bindControls.addAll(bindControlArg.getValues());
    }

    if ((suppressOperationalAttributeUpdatesArg != null) &&
         suppressOperationalAttributeUpdatesArg.isPresent())
    {
      final EnumSet<SuppressType> suppressTypes =
           EnumSet.noneOf(SuppressType.class);
      for (final String s : suppressOperationalAttributeUpdatesArg.getValues())
      {
        if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_ACCESS_TIME))
        {
          suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
        }
        else if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_LOGIN_TIME))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
        }
        else if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_LOGIN_IP))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_IP);
        }
      }

      bindControls.add(new SuppressOperationalAttributeUpdateRequestControl(
           true, suppressTypes));
    }

    return Collections.emptyList();
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
    options.setFollowReferrals(
         ((followReferralsArg != null) && followReferralsArg.isPresent()));
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
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getToolCompletionMessage()
  {
    return completionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Create the sets of controls to include in each type of request.
    final Control[] addControls;
    final Control[] deleteControls;
    final Control[] modifyControls;
    final Control[] modifyDNControls;
    try
    {
      final List<Control> addControlList = new ArrayList<>();
      final List<Control> deleteControlList = new ArrayList<>();
      final List<Control> modifyControlList = new ArrayList<>();
      final List<Control> modifyDNControlList = new ArrayList<>();

      getOperationControls(addControlList, deleteControlList,
           modifyControlList, modifyDNControlList);

      addControls = StaticUtils.toArray(addControlList, Control.class);
      deleteControls = StaticUtils.toArray(deleteControlList, Control.class);
      modifyControls = StaticUtils.toArray(modifyControlList, Control.class);
      modifyDNControls =
           StaticUtils.toArray(modifyDNControlList, Control.class);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      return e.getResultCode();
    }


    // Get the connection pool to use to communicate with the directory
    // server(s).
    final LDAPConnectionPool connectionPool;
    final int numThreads = numThreadsArg.getValue();
    try
    {
      connectionPool = getConnectionPool(numThreads, numThreads, 1, null, null,
           true, null);
      connectionPool.setConnectionPoolName("parallel-update");
      connectionPool.setRetryFailedOperationsDueToInvalidConnections(
           (! neverRetryArg.isPresent()));
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true,
           ERR_PARALLEL_UPDATE_CANNOT_CREATE_POOL.get(
                StaticUtils.getExceptionMessage(e)));
      return e.getResultCode();
    }


    // Create the LDIF reader that will read the changes to process.
    final LDIFReader ldifReader;
    final String encryptionPassphrase;
    try
    {
      final ObjectPair<LDIFReader,String> ldifReaderPair = createLDIFReader();
      ldifReader = ldifReaderPair.getFirst();
      encryptionPassphrase = ldifReaderPair.getSecond();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      connectionPool.close();
      return e.getResultCode();
    }

    final AtomicReference<ResultCode> resultCodeRef =
         new AtomicReference<>(ResultCode.SUCCESS);
    try
    {
      // If the LDIF file is encrypted, then get the ID of the encryption
      // settings definition (if any) used to generate the encryption key.
      final String encryptionSettingsDefinitionID;
      if (encryptionPassphrase == null)
      {
        encryptionSettingsDefinitionID = null;
      }
      else
      {
        encryptionSettingsDefinitionID = getEncryptionSettingsDefinitionID();
      }


      // Create the LDIF writer that will be used to write rejects.
      try
      {
        rejectWriter = createRejectWriter(encryptionPassphrase,
             encryptionSettingsDefinitionID);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        logCompletionMessage(true, e.getMessage());
        return ResultCode.LOCAL_ERROR;
      }


      // If appropriate, create the log writer that will be used to provide a
      // log of the changes that are attempted.
      if (logFileArg.isPresent())
      {
        try
        {
          logWriter = new PrintWriter(logFileArg.getValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_PARALLEL_UPDATE_ERROR_CREATING_LOG_WRITER.get(
                    logFileArg.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          return ResultCode.LOCAL_ERROR;
        }
      }


      // Create The queue that will hold the operations to process.
      final ParallelUpdateOperationQueue operationQueue =
           new ParallelUpdateOperationQueue(this, numThreads,
                (2 * numThreads));


      // Create the rate limiter, if appropriate.
      if (ratePerSecondArg.isPresent())
      {
        rateLimiter = new FixedRateBarrier(1000L, ratePerSecondArg.getValue());
      }
      else
      {
        rateLimiter = null;
      }


      // Create and start all of the threads that will be used to process
      // requests.
      final List<ParallelUpdateOperationThread> operationThreadList =
           new ArrayList<>(numThreads);
      for (int i=1; i <= numThreads; i++)
      {
        final ParallelUpdateOperationThread operationThread =
             new ParallelUpdateOperationThread(this, connectionPool,
                  operationQueue, i, rateLimiter, addControls, deleteControls,
                  modifyControls, modifyDNControls,
                  allowUndeleteArg.isPresent());
        operationThreadList.add(operationThread);
        operationThread.start();
      }


      // Create a progress monitor that will be used to report periodic status
      // updates about the processing that has been performed.
      final ParallelUpdateProgressMonitor progressMonitor =
           new ParallelUpdateProgressMonitor(this);
      try
      {
        processingStartTimeMillis = System.currentTimeMillis();
        progressMonitor.start();

        while (! shouldAbort.get())
        {
          final LDIFChangeRecord changeRecord;
          try
          {
            changeRecord = ldifReader.readChangeRecord(
                 defaultAddArg.isPresent());
          }
          catch (final LDIFException e)
          {
            Debug.debugException(e);
            if (e.mayContinueReading())
            {
              final String message =
                   ERR_PARALLEL_UPDATE_RECOVERABLE_LDIF_EXCEPTION.get(
                        ldifFileArg.getValue().getAbsolutePath(),
                        e.getMessage());
              logMessage(message);
              reject(null,
                   new LDAPException(ResultCode.DECODING_ERROR, message, e));
              opsAttempted.incrementAndGet();
              continue;
            }
            else
            {
              shouldAbort.set(true);
              final String message =
                   ERR_PARALLEL_UPDATE_UNRECOVERABLE_LDIF_EXCEPTION.get(
                        ldifFileArg.getValue().getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e));
              reject(null,
                   new LDAPException(ResultCode.DECODING_ERROR, message, e));
              logCompletionMessage(true, message);
              return ResultCode.DECODING_ERROR;
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            shouldAbort.set(true);
            final String message =
                 ERR_PARALLEL_UPDATE_ERROR_READING_LDIF_FILE.get(
                      ldifFileArg.getValue().getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e));
            reject(null,
                 new LDAPException(ResultCode.LOCAL_ERROR, message, e));
            logCompletionMessage(true, message);
            return ResultCode.LOCAL_ERROR;
          }

          if (changeRecord == null)
          {
            // We've reached the end of the LDIF file.
            break;
          }
          else
          {
            try
            {
              operationQueue.addChangeRecord(changeRecord);
            }
            catch (final Exception e)
            {
              Debug.debugException(e);

              // This indicates that the attempt to enqueue the change record
              // was interrupted.  This shouldn't happen, but if it does, then
              // mark it to be retried.
              final LDAPException le = new LDAPException(ResultCode.LOCAL_ERROR,
                   ERR_PARALLEL_UPDATE_ENQUEUE_FAILED.get(
                        StaticUtils.getExceptionMessage(e)),
                   e);
              retry(changeRecord, le);
            }
          }
        }


        // If a failure was encountered, then abort.
        if (shouldAbort.get())
        {
          resultCodeRef.compareAndSet(ResultCode.SUCCESS,
               ResultCode.LOCAL_ERROR);
          return resultCodeRef.get();
        }


        // Indicate that we've reached the end of the LDIF file.
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_PARALLEL_UPDATE_END_OF_LDIF.get());
        out();


        // Wait for the operation queue to become idle so that we know there
        // are no more outstanding operations to be processed.
        operationQueue.waitUntilIdle();
        initialAttempted = opsAttempted.get();
        initialSucceeded = opsSucceeded.get();


        // If there are any operations to retry, then do so now.
        Map<DN,List<ObjectPair<LDIFChangeRecord,LDAPException>>> retryQueueCopy;
        synchronized (retryQueue)
        {
          retryQueueCopy = new TreeMap<>(retryQueue);
          retryQueue.clear();
        }

        int lastRetryQueueSize = 0;
        while ((! retryQueueCopy.isEmpty()) &&
             (retryQueueCopy.size() != lastRetryQueueSize))
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_PARALLEL_UPDATE_BEGINNING_RETRY.get(retryQueueCopy.size()));
          out();


          for (final
               Map.Entry<DN,List<ObjectPair<LDIFChangeRecord,LDAPException>>>
               e : retryQueueCopy.entrySet())
          {
            for (final ObjectPair<LDIFChangeRecord,LDAPException> p :
              e.getValue())
            {
              if (shouldAbort.get())
              {
                resultCodeRef.compareAndSet(ResultCode.SUCCESS,
                     ResultCode.LOCAL_ERROR);
                return resultCodeRef.get();
              }

              final LDIFChangeRecord changeRecord = p.getFirst();
              try
              {
                operationQueue.addChangeRecord(changeRecord);
                retryQueueSize.decrementAndGet();
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);

                // This indicates that the attempt to enqueue the change record
                // was interrupted.  This shouldn't happen, but if it does, then
                // mark it to be retried.
                final LDAPException le = new LDAPException(
                     ResultCode.LOCAL_ERROR,
                     ERR_PARALLEL_UPDATE_ENQUEUE_FAILED.get(
                          StaticUtils.getExceptionMessage(ex)),
                     ex);
                retry(changeRecord, le);
              }
            }
          }


          operationQueue.waitUntilIdle();
          lastRetryQueueSize = retryQueueCopy.size();

          synchronized (retryQueue)
          {
            retryQueueCopy = new TreeMap<>(retryQueue);
            retryQueue.clear();
          }
        }


        // If we've gotten here, then it means that either the retry queue
        // (NOTE:  we actually need to use retryQueueCopy) is empty or none of
        // the retry attempts succeeded on the last pass.  If it's the latter,
        // then reject any of the remaining operations.
        synchronized (retryQueue)
        {
          final int remainingToRetry = retryQueueCopy.size();
          if (remainingToRetry > 0)
          {
            if (remainingToRetry == 1)
            {
              wrapErr(0, WRAP_COLUMN,
                   ERR_PARALLEL_UPDATE_NO_PROGRESS_ONE.get());
            }
            else
            {
              wrapErr(0, WRAP_COLUMN,
                   ERR_PARALLEL_UPDATE_NO_PROGRESS_MULTIPLE.get(
                        remainingToRetry));
            }
          }

          for (final
               Map.Entry<DN,List<ObjectPair<LDIFChangeRecord,LDAPException>>>
               e : retryQueueCopy.entrySet())
          {
            for (final ObjectPair<LDIFChangeRecord,LDAPException> p :
                 e.getValue())
            {
              reject(p.getFirst(), p.getSecond());
              retryQueueSize.decrementAndGet();
            }
          }
        }
      }
      finally
      {
        operationQueue.setEndOfLDIF();
        operationQueue.waitUntilIdle();

        for (final ParallelUpdateOperationThread operationThread :
             operationThreadList)
        {
          try
          {
            operationThread.join();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            logCompletionMessage(true,
                 ERR_PARALLEL_UPDATE_CANNOT_JOIN_THREAD.get(
                      operationThread.getName(),
                      StaticUtils.getExceptionMessage(e)));
            resultCodeRef.compareAndSet(ResultCode.SUCCESS,
                 ResultCode.LOCAL_ERROR);
          }
        }

        try
        {
          progressMonitor.stopRunning();
          progressMonitor.join();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_PARALLEL_UPDATE_CANNOT_JOIN_PROGRESS_MONITOR.get(
                    StaticUtils.getExceptionMessage(e)));
          resultCodeRef.compareAndSet(ResultCode.SUCCESS,
               ResultCode.LOCAL_ERROR);
        }
      }
    }
    finally
    {
      connectionPool.close();

      if (rejectWriter != null)
      {
        try
        {
          rejectWriter.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_PARALLEL_UPDATE_ERROR_CLOSING_REJECT_WRITER.get(
                    rejectFileArg.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          resultCodeRef.compareAndSet(ResultCode.SUCCESS,
               ResultCode.LOCAL_ERROR);
        }
      }

      if (logWriter != null)
      {
        try
        {
          logWriter.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          logCompletionMessage(true,
               ERR_PARALLEL_UPDATE_ERROR_CLOSING_LOG_WRITER.get(
                    logFileArg.getValue().getAbsolutePath(),
                    StaticUtils.getExceptionMessage(e)));
          resultCodeRef.compareAndSet(ResultCode.SUCCESS,
               ResultCode.LOCAL_ERROR);
        }
      }

      try
      {
        ldifReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        logCompletionMessage(true,
             WARN_PARALLEL_UPDATE_ERROR_CLOSING_READER.get(
                  ldifFileArg.getValue().getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)));
        resultCodeRef.compareAndSet(ResultCode.SUCCESS, ResultCode.LOCAL_ERROR);
      }
    }


    // If we've gotten here, then processing has completed.  Print some summary
    // messages and return an appropriate result code.
    final long processingDurationMillis =
         System.currentTimeMillis() - processingStartTimeMillis;
    final long numAttempts = opsAttempted.get();
    final long numSuccesses = opsSucceeded.get();
    final long numRejects = opsRejected.get();

    final long retryAttempts = numAttempts - initialAttempted;
    final long retrySuccesses = numSuccesses - initialSucceeded;

    out(INFO_PARALLEL_UPDATE_DONE.get(getToolName()));
    out(INFO_PARALLEL_UPDATE_SUMMARY_OPS_ATTEMPTED.get(numAttempts));

    if (retryAttempts > 0L)
    {
      out(INFO_PARALLEL_UPDATE_SUMMARY_INITIAL_ATTEMPTS.get(initialAttempted));
      out(INFO_PARALLEL_UPDATE_SUMMARY_RETRY_ATTEMPTS.get(retryAttempts));
    }

    out(INFO_PARALLEL_UPDATE_SUMMARY_OPS_SUCCEEDED.get(numSuccesses));

    if (retryAttempts > 0)
    {
      out(INFO_PARALLEL_UPDATED_OPS_SUCCEEDED_INITIAL.get(initialSucceeded));
      out(INFO_PARALLEL_UPDATED_OPS_SUCCEEDED_RETRY.get(retrySuccesses));
    }

    out(INFO_PARALLEL_UPDATE_SUMMARY_OPS_REJECTED.get(numRejects));
    out(INFO_PARALLEL_UPDATE_SUMMARY_DURATION.get(
         StaticUtils.millisToHumanReadableDuration(processingDurationMillis)));

    if ((numAttempts > 0L) && (processingDurationMillis > 0L))
    {
      final double attemptsPerSecond =
           numAttempts * 1_000.0d / processingDurationMillis;
      final DecimalFormat decimalFormat = new DecimalFormat("0.000");
      out(INFO_PARALLEL_UPDATE_SUMMARY_RATE.get(
           decimalFormat.format(attemptsPerSecond)));
    }


    if (numRejects == 0L)
    {
      completionMessage.compareAndSet(null,
           INFO_PARALLEL_UPDATE_COMPLETION_MESSAGE_ALL_SUCCEEDED.get(
                getToolName()));
    }
    else if (numRejects == 1L)
    {
      completionMessage.compareAndSet(null,
           INFO_PARALLEL_UPDATE_COMPLETION_MESSAGE_ONE_REJECTED.get(
                getToolName()));
    }
    else
    {
      completionMessage.compareAndSet(null,
           INFO_PARALLEL_UPDATE_COMPLETION_MESSAGE_MULTIPLE_REJECTED.get(
                getToolName(), numRejects));
    }


    ResultCode finalResultCode = resultCodeRef.get();
    if ((finalResultCode == ResultCode.SUCCESS) &&
         useFirstRejectResultCodeAsExitCodeArg.isPresent() &&
         (firstRejectResultCode.get() != null))
    {
      finalResultCode = firstRejectResultCode.get();
    }

    return finalResultCode;
  }



  /**
   * Updates the provided lists with the appropriate controls to include in
   * each type of request.
   *
   * @param  addControls       The list that should be updated with controls to
   *                           include in add requests.  It must not be
   *                           {@code null} and must be updatable.
   * @param  deleteControls    The list that should be updated with controls to
   *                           include in delete requests.  It must not be
   *                           {@code null} and must be updatable.
   * @param  modifyControls    The list that should be updated with controls to
   *                           include in modify requests.  It must not be
   *                           {@code null} and must be updatable.
   * @param  modifyDNControls  The list that should be updated with controls to
   *                           include in modify DN requests.  It must not be
   *                           {@code null} and must be updatable.
   *
   * @throws  LDAPException  If a problem is encountered while creating any of
   *                         the controls.
   */
  private void getOperationControls(
                    @NotNull final List<Control> addControls,
                    @NotNull final List<Control> deleteControls,
                    @NotNull final List<Control> modifyControls,
                    @NotNull final List<Control> modifyDNControls)
          throws LDAPException
  {
    if (addControlArg.isPresent())
    {
      addControls.addAll(addControlArg.getValues());
    }

    if (deleteControlArg.isPresent())
    {
      deleteControls.addAll(deleteControlArg.getValues());
    }

    if (modifyControlArg.isPresent())
    {
      modifyControls.addAll(modifyControlArg.getValues());
    }

    if (modifyDNControlArg.isPresent())
    {
      modifyDNControls.addAll(modifyDNControlArg.getValues());
    }

    if (proxyAsArg.isPresent())
    {
      final ProxiedAuthorizationV2RequestControl c =
           new ProxiedAuthorizationV2RequestControl(proxyAsArg.getValue());
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }
    else if (proxyV1AsArg.isPresent())
    {
      final ProxiedAuthorizationV1RequestControl c =
           new ProxiedAuthorizationV1RequestControl(proxyV1AsArg.getValue());
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }

    if (usePermissiveModifyArg.isPresent())
    {
      modifyControls.add(new PermissiveModifyRequestControl(true));
    }

    if (ignoreNoUserModificationArg.isPresent())
    {
      final IgnoreNoUserModificationRequestControl c =
           new IgnoreNoUserModificationRequestControl();
      addControls.add(c);
      modifyControls.add(c);
    }

    if (useManageDsaITArg.isPresent())
    {
      final ManageDsaITRequestControl c = new ManageDsaITRequestControl(true);
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }

    if (nameWithEntryUUIDArg.isPresent())
    {
      addControls.add(new NameWithEntryUUIDRequestControl(true));
    }

    if (softDeleteArg.isPresent())
    {
      deleteControls.add(new SoftDeleteRequestControl(true, true));
    }
    else if (hardDeleteArg.isPresent())
    {
      deleteControls.add(new HardDeleteRequestControl(true));
    }

    if (operationPurposeArg.isPresent())
    {
      final OperationPurposeRequestControl c =
           new OperationPurposeRequestControl(false, "parallel-update",
                Version.NUMERIC_VERSION_STRING,
                ParallelUpdate.class.getName() + ".getOperationControls",
                operationPurposeArg.getValue());
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }

    if (replicationRepairArg.isPresent())
    {
      final ReplicationRepairRequestControl c =
           new ReplicationRepairRequestControl();
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }

    if (suppressReferentialIntegrityUpdatesArg.isPresent())
    {
      final SuppressReferentialIntegrityUpdatesRequestControl c =
           new SuppressReferentialIntegrityUpdatesRequestControl(true);
      deleteControls.add(c);
      modifyDNControls.add(c);
    }


    if (useAssuredReplicationArg.isPresent())
    {
      final AssuredReplicationLocalLevel localLevel;
      if (assuredReplicationLocalLevelArg.isPresent())
      {
        final String localLevelStr = StaticUtils.toLowerCase(
             assuredReplicationLocalLevelArg.getValue());
        switch (localLevelStr)
        {
          case ASSURED_REPLICATION_LOCAL_LEVEL_NONE:
            localLevel = AssuredReplicationLocalLevel.NONE;
            break;
          case ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER:
            localLevel = AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER;
            break;
          case ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS:
            localLevel = AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS;
            break;
          default:
            // This should never happen.
            localLevel = null;
            break;
        }
      }
      else
      {
        localLevel = null;
      }

      final AssuredReplicationRemoteLevel remoteLevel;
      if (assuredReplicationRemoteLevelArg.isPresent())
      {
        final String remoteLevelStr = StaticUtils.toLowerCase(
             assuredReplicationRemoteLevelArg.getValue());
        switch (remoteLevelStr)
        {
          case ASSURED_REPLICATION_REMOTE_LEVEL_NONE:
            remoteLevel = AssuredReplicationRemoteLevel.NONE;
            break;
          case ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION:
            remoteLevel = AssuredReplicationRemoteLevel.
                 RECEIVED_ANY_REMOTE_LOCATION;
            break;
          case ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS:
            remoteLevel = AssuredReplicationRemoteLevel.
                 RECEIVED_ALL_REMOTE_LOCATIONS;
            break;
          case ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS:
            remoteLevel = AssuredReplicationRemoteLevel.
                 PROCESSED_ALL_REMOTE_SERVERS;
            break;
          default:
            // This should never happen.
            remoteLevel = null;
            break;
        }
      }
      else
      {
        remoteLevel = null;
      }

      final Long timeoutMillis;
      if (assuredReplicationTimeoutArg.isPresent())
      {
        timeoutMillis = assuredReplicationTimeoutArg.getValue(
             TimeUnit.MILLISECONDS);
      }
      else
      {
        timeoutMillis = null;
      }

      final AssuredReplicationRequestControl c =
           new AssuredReplicationRequestControl(true, localLevel, null,
                remoteLevel, null, timeoutMillis, false);
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }


    if (passwordUpdateBehaviorArg.isPresent())
    {
      final PasswordUpdateBehaviorRequestControlProperties properties =
           new PasswordUpdateBehaviorRequestControlProperties();
      for (final String argValue : passwordUpdateBehaviorArg.getValues())
      {
        final int equalPos = argValue.indexOf('=');
        if (equalPos < 0)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_PARALLEL_UPDATE_MALFORMED_PW_UPDATE_VALUE.get(
                    argValue, passwordUpdateBehaviorArg.getIdentifierString()));
        }

        final String propertyName = argValue.substring(0, equalPos).trim();
        final String lowerName = StaticUtils.toLowerCase(propertyName);
        switch (lowerName)
        {
          case PW_UPDATE_BEHAVIOR_NAME_IS_SELF_CHANGE:
            properties.setIsSelfChange(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_ALLOW_PRE_ENCODED_PW:
            properties.setAllowPreEncodedPassword(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_SKIP_PW_VALIDATION:
            properties.setSkipPasswordValidation(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_IGNORE_PW_HISTORY:
            properties.setIgnorePasswordHistory(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_IGNORE_MIN_PW_AGE:
            properties.setIgnoreMinimumPasswordAge(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_MUST_CHANGE_PW:
            properties.setMustChangePassword(
                 getBooleanPWUpdateBehaviorValue(argValue));
            break;
          case PW_UPDATE_BEHAVIOR_NAME_PW_STORAGE_SCHEME:
            final String propertyValue = argValue.substring(equalPos+1).trim();
            properties.setPasswordStorageScheme(propertyValue);
            break;
          default:
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_PARALLEL_UPDATE_UNKNOWN_PW_UPDATE_PROP.get(argValue,
                      passwordUpdateBehaviorArg.getIdentifierString(),
                      PW_UPDATE_BEHAVIOR_NAME_IS_SELF_CHANGE,
                      PW_UPDATE_BEHAVIOR_NAME_ALLOW_PRE_ENCODED_PW,
                      PW_UPDATE_BEHAVIOR_NAME_SKIP_PW_VALIDATION,
                      PW_UPDATE_BEHAVIOR_NAME_IGNORE_PW_HISTORY,
                      PW_UPDATE_BEHAVIOR_NAME_IGNORE_MIN_PW_AGE,
                      PW_UPDATE_BEHAVIOR_NAME_PW_STORAGE_SCHEME,
                      PW_UPDATE_BEHAVIOR_NAME_MUST_CHANGE_PW));
        }
      }

      final PasswordUpdateBehaviorRequestControl c =
           new PasswordUpdateBehaviorRequestControl(properties, true);
      addControls.add(c);
      modifyControls.add(c);
    }


    if (suppressOperationalAttributeUpdatesArg.isPresent())
    {
      final EnumSet<SuppressType> suppressTypes =
           EnumSet.noneOf(SuppressType.class);
      for (final String s : suppressOperationalAttributeUpdatesArg.getValues())
      {
        if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_ACCESS_TIME))
        {
          suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
        }
        else if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_LOGIN_TIME))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
        }
        else if (s.equalsIgnoreCase(SUPPRESS_OP_ATTR_LAST_LOGIN_IP))
        {
          suppressTypes.add(SuppressType.LAST_LOGIN_IP);
        }
      }

      final SuppressOperationalAttributeUpdateRequestControl c =
           new SuppressOperationalAttributeUpdateRequestControl(true,
                suppressTypes);
      addControls.add(c);
      deleteControls.add(c);
      modifyControls.add(c);
      modifyDNControls.add(c);
    }
  }



  /**
   * Retrieves the value from the provided name-value pair and parses it as a
   * boolean.
   *
   * @param  nameValuePair  The name-value pair to be parsed.  It must not be
   *                        {@code null} and it must contain an equal sign.
   *
   * @return  The boolean value parsed from the provided name-value pair.
   *
   * @throws  LDAPException  If the value could not be parsed as a boolean.
   */
  private boolean getBooleanPWUpdateBehaviorValue(
               @NotNull final String nameValuePair)
          throws LDAPException
  {
    final int equalPos = nameValuePair.indexOf('=');
    final String propertyValue = nameValuePair.substring(equalPos+1).trim();
    final String lowerValue = StaticUtils.toLowerCase(propertyValue);
    switch (lowerValue)
    {
      case "true":
      case "t":
      case "yes":
      case "on":
      case "1":
        return true;
      case "false":
      case "f":
      case "no":
      case "off":
      case "0":
        return false;
      default:
        final String propertyName = nameValuePair.substring(0, equalPos).trim();
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_PARALLEL_UPDATE_PW_UPDATE_VALUE_NOT_BOOLEAN.get(nameValuePair,
                  passwordUpdateBehaviorArg.getIdentifierString(),
                  propertyName));
    }
  }



  /**
   * Creates the LDIF reader to use to read the changes to process.
   *
   * @return  An object pair in which the first element is the LDIF reader and
   *          the second element is the passphrase used to encrypt the contents
   *          of the LDIF file (or {@code null} if the LDIF file is not
   *          encrypted).
   *
   * @throws  LDAPException  If a problem occurs while trying to create the LDIF
   *                         reader.
   */
  @NotNull()
  private ObjectPair<LDIFReader,String> createLDIFReader()
          throws LDAPException
  {
    final File ldifFile = ldifFileArg.getValue();

    try
    {
      final String encryptionPassphraseFromFile;
      if (encryptionPassphraseFileArg.isPresent())
      {
        final char[] pwChars = getPasswordFileReader().readPassword(
             encryptionPassphraseFileArg.getValue());
        encryptionPassphraseFromFile = new String(pwChars);
        Arrays.fill(pwChars, '\u0000');
      }
      else
      {
        encryptionPassphraseFromFile = null;
      }

      final ObjectPair<InputStream,String> inputStreamPair =
           ToolUtils.getInputStreamForLDIFFiles(
                Collections.singletonList(ldifFile),
                encryptionPassphraseFromFile, getOut(), getErr());

      final LDIFReader ldifReader = new LDIFReader(inputStreamPair.getFirst());
      final String encryptionPassphrase = inputStreamPair.getSecond();
      return new ObjectPair<>(ldifReader, encryptionPassphrase);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_PARALLEL_UPDATE_CANNOT_CREATE_LDIF_READER.get(
                ldifFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Attempts to retrieve the ID of the encryption settings definition used to
   * encrypt the LDIF file.  This method should only be used if the LDIF file is
   * known to be encrypted.
   *
   * @return  The ID of the encryption settings definition used to encrypt the
   *          LDIF file, or {code null} if it was not encrypted with a
   *          passphrase obtained from an encryption settings definition (or if
   *          an error occurred while attempting to retrieve the ID).
   */
  @Nullable()
  private String getEncryptionSettingsDefinitionID()
  {
    try (FileInputStream inputStream =
              new FileInputStream(ldifFileArg.getValue()))
    {
      final PassphraseEncryptedStreamHeader encryptionHeader =
           PassphraseEncryptedStreamHeader.readFrom(inputStream, null);
      return encryptionHeader.getKeyIdentifier();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Creates the LDIF writer that will be used to write information about
   * rejected entries.  If the LDIF input file was encrypted, then the reject
   * file will be encrypted with the same settings, and it will also be
   * compressed (regardless of whether the input file was compressed).
   *
   * @param  encryptionPassphrase            The passphrase used to encrypt the
   *                                         input file.  This may be
   *                                         {@code null} if the input file was
   *                                         not encrypted.
   * @param  encryptionSettingsDefinitionID  The ID for the encryption settings
   *                                         definition with which the
   *                                         passphrase is associated.  It may
   *                                         be {@code null} if the input file
   *                                         was not encrypted, or if the
   *                                         encryption passphrase was not
   *                                         obtained from an encryption
   *                                         settings definition.
   *
   * @return  The LDIF writer to which rejects should be written.
   *
   * @throws  LDAPException  If a problem occurs while creating the reject
   *                         writer.
   */
  @NotNull()
  private LDIFWriter createRejectWriter(
               @Nullable final String encryptionPassphrase,
               @Nullable final String encryptionSettingsDefinitionID)
          throws LDAPException
  {
    final File rejectFile = rejectFileArg.getValue();

    OutputStream outputStream = null;
    try
    {
      outputStream = new FileOutputStream(rejectFile);

      if (encryptionPassphrase != null)
      {
        outputStream = new PassphraseEncryptedOutputStream(encryptionPassphrase,
             outputStream, encryptionSettingsDefinitionID, true, true);
        outputStream = new GZIPOutputStream(outputStream);
      }


      final LDIFWriter ldifWriter = new LDIFWriter(outputStream);

      // Set the wrap column to the maximum allowed value to ensure that
      // comments dont' get wrapped.
      ldifWriter.setWrapColumn(Integer.MAX_VALUE);

      return ldifWriter;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (outputStream != null)
      {
        try
        {
          outputStream.close();
        }
        catch (final Exception e2)
        {
          Debug.debugException(e2);
        }
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_PARALLEL_UPDATE_ERROR_CREATING_REJECT_WRITER.get(
                rejectFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Writes the provided message to standard output or standard error and sets
   * it as the completion message if there isn't one already.
   *
   * @param  isError  Indicates whether the message represents an error.
   * @param  message  The message to log.
   */
  private void logCompletionMessage(final boolean isError,
                                    @NotNull final String message)
  {
    completionMessage.compareAndSet(null, message);
    logMessage(message);
    if (isError)
    {
      wrapErr(0, WRAP_COLUMN, message);
    }
    else
    {
      wrapOut(0, WRAP_COLUMN, message);
    }
  }



  /**
   * Logs the provided message if logging is enabled.
   *
   * @param  messageElements  The elements that make up the message to log.
   */
  private void logMessage(@NotNull final Object... messageElements)
  {
    if (logWriter != null)
    {
      SimpleDateFormat timestampFormatter = timestampFormatters.get();
      if (timestampFormatter == null)
      {
        timestampFormatter =
             new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
        timestampFormatters.set(timestampFormatter);
      }

      final String timestamp = timestampFormatter.format(new Date());

      final StringBuilder message = new StringBuilder();
      message.append('[');
      message.append(timestamp);
      message.append("] ");
      for (final Object o : messageElements)
      {
        message.append(String.valueOf(o));
      }

      try
      {
        logWriter.println(message);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        final String errorMessage =
             ERR_PARALLEL_UPDATE_CANNOT_WRITE_LOG_MESSAGE.get(
                  message.toString(), logFileArg.getValue().getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e));
        wrapErr(0, WRAP_COLUMN, errorMessage);
        completionMessage.compareAndSet(null, errorMessage);
        shouldAbort.set(true);
      }
    }
  }



  /**
   * Indicates that processing for an operation completed successfully.
   *
   * @param  changeRecord              The LDIF change record for the operation.
   *                                   It must not be {@code null}.
   * @param  processingDurationMillis  The length of time required to process
   *                                   the operation, in milliseconds.
   */
  void opCompletedSuccessfully(@NotNull final LDIFChangeRecord changeRecord,
                               final long processingDurationMillis)
  {
    opsAttempted.incrementAndGet();
    opsSucceeded.incrementAndGet();
    totalOpDurationMillis.addAndGet(processingDurationMillis);
    logMessage(changeRecord.getDN(), " ",
         changeRecord.getChangeType().getName(), " SUCCESS 0 ");
  }



  /**
   * Indicates that processing for an operation failed.  Depending on the nature
   * of the failure, it either be added to the retry queue if it is potentially
   * an operation that could be retried (e.g., an operation that failed because
   * it depended on an entry that was added later in the LDIF), or will be added
   * to the reject file if it is determined that it is not a failure that may be
   * resolved by a later change.
   *
   * @param  changeRecord              The LDIF change record for the operation.
   *                                   It must not be {@code null}.
   * @param  ldapException             The LDAP exception that was caught to
   *                                   indicate that the operation failed.  It
   *                                   must not be {@code null}.
   * @param  processingDurationMillis  The length of time required to process
   *                                   the operation, in milliseconds.
   */
  void opFailed(@NotNull final LDIFChangeRecord changeRecord,
                @NotNull final LDAPException ldapException,
                final long processingDurationMillis)
  {
    opsAttempted.incrementAndGet();
    totalOpDurationMillis.addAndGet(processingDurationMillis);

    switch (ldapException.getResultCode().intValue())
    {
      case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
      case ResultCode.BUSY_INT_VALUE:
      case ResultCode.UNAVAILABLE_INT_VALUE:
      case ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE:
      case ResultCode.SERVER_DOWN_INT_VALUE:
      case ResultCode.CONNECT_ERROR_INT_VALUE:
        retry(changeRecord, ldapException);
        break;
      default:
        reject(changeRecord, ldapException);
        break;
    }
  }



  /**
   * Adds the provided operation to the retry queue.
   *
   * @param  changeRecord   The LDIF change record for the operation.
   * @param  ldapException  The LDAP exception that was caught to indicate that
   *                        the operation failed.
   */
  private void retry(@NotNull final LDIFChangeRecord changeRecord,
                     @NotNull final LDAPException ldapException)
  {
    if (neverRetryArg.isPresent())
    {
      reject(changeRecord, ldapException);
      return;
    }

    final DN parsedDN;
    try
    {
      parsedDN = changeRecord.getParsedDN();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);

      // This should never happen, but if it does, then reject the change.
      reject(changeRecord, ldapException);
      return;
    }

    logMessage(changeRecord.getDN(), " ",
         changeRecord.getChangeType().getName(), " RETRY ",
         ldapException.getResultCode(), " ", ldapException.getMessage());

    synchronized (retryQueue)
    {
      List<ObjectPair<LDIFChangeRecord,LDAPException>> changeList =
           retryQueue.get(parsedDN);

      if (changeList == null)
      {
        changeList = new LinkedList<>();
        retryQueue.put(parsedDN, changeList);
      }

      changeList.add(new ObjectPair<>(changeRecord, ldapException));
      retryQueueSize.incrementAndGet();
    }
  }



  /**
   * Adds the provided operation to the reject file.
   *
   * @param  changeRecord   The LDIF change record for the operation.
   * @param  ldapException  The LDAP exception that was caught to indicate that
   *                        the operation failed.
   */
  void reject(@Nullable final LDIFChangeRecord changeRecord,
              @NotNull final LDAPException ldapException)
  {
    opsRejected.incrementAndGet();

    final ResultCode resultCode = ldapException.getResultCode();
    if (resultCode != ResultCode.SUCCESS)
    {
      firstRejectResultCode.compareAndSet(null, resultCode);
    }

    final StringBuilder commentBuffer = new StringBuilder();
    for (final String line :
         ResultUtils.formatResult(ldapException, false, 0, 0))
    {
      if (commentBuffer.length() > 0)
      {
        commentBuffer.append(StaticUtils.EOL);
      }
      commentBuffer.append(line);
    }
    final String comment = commentBuffer.toString();

    try
    {
      if (changeRecord != null)
      {
        logMessage(changeRecord.getDN(), " ",
            changeRecord.getChangeType().getName(), " REJECT ", resultCode, " ",
             ldapException.getMessage());

        rejectWriter.writeChangeRecord(changeRecord, comment);
      }
      else
      {
        rejectWriter.writeComment(comment, true, true);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String errorMessage = ERR_PARALLEL_UPDATE_CANNOT_WRITE_REJECT.get(
           changeRecord.toString(),
           ERR_PARALLEL_UPDATE_REJECT_COMMENT.get(String.valueOf(resultCode),
                ldapException.getMessage()),
           StaticUtils.getExceptionMessage(e));
        wrapErr(0, WRAP_COLUMN, errorMessage);
        completionMessage.compareAndSet(null, errorMessage);
        shouldAbort.set(true);
    }
  }



  /**
   * Prints information about the processing performed by this program to
   * standard output.
   */
  void printIntervalData()
  {
    final long currentAttempts = opsAttempted.get();
    final long currentSuccesses = opsSucceeded.get();
    final long currentReject = opsRejected.get();
    final long currentRetry = retryQueueSize.get();
    final long currentDurationMillis = totalOpDurationMillis.get();
    final long currentTimeMillis = System.currentTimeMillis();
    final long totalDurationMillis =
         currentTimeMillis - processingStartTimeMillis;

    final long avgRate;
    if (totalDurationMillis == 0L)
    {
      avgRate = 0L;
    }
    else
    {
      avgRate = 1000L * currentAttempts / totalDurationMillis;
    }

    final long avgDurationMillis;
    if (currentAttempts == 0L)
    {
      avgDurationMillis = 0L;
    }
    else
    {
      avgDurationMillis = currentDurationMillis / currentAttempts;
    }

    final long recentDurationMillis;
    if (currentAttempts == lastOpsAttempted)
    {
      recentDurationMillis = 0L;
    }
    else
    {
      recentDurationMillis = (currentDurationMillis - lastTotalDurationMillis) /
           (currentAttempts - lastOpsAttempted);
    }

    final long recentRate;
    if (lastOpsAttempted == 0)
    {
      out(" Attempts Successes   Rejects   ToRetry  AvgOps/S " +
          " RctOps/S  AvgDurMS  RctDurMS");
      out("--------- --------- --------- --------- --------- " +
          "--------- --------- ---------");
      recentRate = avgRate;
    }
    else if (currentTimeMillis == lastUpdateTimeMillis)
    {
      recentRate = 0L;
    }
    else
    {
      recentRate = 1000L * (currentAttempts - lastOpsAttempted) /
                   (currentTimeMillis - lastUpdateTimeMillis);
    }

    final StringBuilder buffer = new StringBuilder(80);
    appendJustified(currentAttempts, buffer, true);
    appendJustified(currentSuccesses, buffer, true);
    appendJustified(currentReject, buffer, true);
    appendJustified(currentRetry, buffer, true);
    appendJustified(avgRate, buffer, true);
    appendJustified(recentRate, buffer, true);
    appendJustified(avgDurationMillis, buffer, true);
    appendJustified(recentDurationMillis, buffer, false);

    out(buffer.toString());

    lastOpsAttempted = currentAttempts;
    lastTotalDurationMillis = currentDurationMillis;
    lastUpdateTimeMillis = currentTimeMillis;
  }



  /**
   * Appends the provided number to the buffer, right justified in nine columns.
   *
   * @param  value     The value to be appended to the buffer.
   * @param  buffer    The buffer to which the value should be appended.
   * @param  addSpace  Indicates whether to append a space after the number.
   */
  static void appendJustified(final long value,
                              @NotNull final StringBuilder buffer,
                              final boolean addSpace)
  {
    final String valueStr = String.valueOf(value);
    switch (valueStr.length())
    {
      case 1:
        buffer.append("        ");
        break;
      case 2:
        buffer.append("       ");
        break;
      case 3:
        buffer.append("      ");
        break;
      case 4:
        buffer.append("     ");
        break;
      case 5:
        buffer.append("    ");
        break;
      case 6:
        buffer.append("   ");
        break;
      case 7:
        buffer.append("  ");
        break;
      case 8:
        buffer.append(' ');
        break;
    }

    buffer.append(value);

    if (addSpace)
    {
      buffer.append(' ');
    }
  }



  /**
   * Retrieves the total number of operations attempted.  This should only be
   * called after all tool processing has completed.
   *
   * @return  The total number of operations attempted.
   */
  public long getTotalAttemptCount()
  {
    return opsAttempted.get();
  }



  /**
   * Retrieves the number of operations attempted on the initial pass through
   * the LDIF file (that is, operations for which no retry attempts was made).
   * This should only be called after all tool processing has completed.
   *
   * @return  The number of operations attempted on the initial pass through the
   *          LDIF file.
   */
  public long getInitialAttemptCount()
  {
    return initialAttempted;
  }



  /**
   * Retrieves the number of retry attempts made for operations that did not
   * complete successfully on their first attempt.  This should only be called
   * after all tool processing has completed.
   *
   * @return  The number of retry attempts made for operations that did not
   *          complete successfully on their first attempt.
   */
  public long getRetryAttemptCount()
  {
    return opsAttempted.get() - initialAttempted;
  }



  /**
   * Retrieves the total number of operations that completed successfully.  This
   * should only be called after all tool processing has completed.
   *
   * @return  The total number of operations that completed successfully.
   */
  public long getTotalSuccessCount()
  {
    return opsSucceeded.get();
  }



  /**
   * Retrieves the number of operations that completed successfully on their
   * first attempt.  This should only be called after all tool processing has
   * completed.
   *
   * @return  The total number of operations that completed successfully on
   *          their first attempt.
   */
  public long getInitialSuccessCount()
  {
    return initialSucceeded;
  }



  /**
   * Retrieves the number of operations that did not complete completed
   * successfully on their initial attempt but did succeed on a retry attempt.
   * This should only be called after all tool processing has completed.
   *
   * @return  The number of operations that completed successfully on a retry
   *          attempt.
   */
  public long getRetrySuccessCount()
  {
    return opsSucceeded.get() - initialSucceeded;
  }



  /**
   * Retrieves the number of operations that were rejected and did not complete
   * successfully during any of the attempts.  This should only be called after
   * all tool processing has completed.
   *
   * @return  The number of operations that were rejected.
   */
  public long getRejectCount()
  {
    return opsRejected.get();
  }



  /**
   * Retrieves the total length of time, in milliseconds, spent processing
   * operations.  This should only be called after all tool processing has
   * completed.  Note that when running with multiple threads, this can exceed
   * the length of time spent running the tool because multiple operations can
   * be processed in parallel.
   *
   * @return  The total length of time, in milliseconds, spent processing
   *          operations.
   */
  public long getTotalOpDurationMillis()
  {
    return totalOpDurationMillis.get();
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
  protected void doShutdownHookProcessing(@Nullable final ResultCode resultCode)
  {
    shouldAbort.set(true);

    final FixedRateBarrier b = rateLimiter;
    if (b != null)
    {
      b.shutdownRequested();
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
    final String message;
    if (notification.getDiagnosticMessage() == null)
    {
      message = INFO_PARALLEL_UPDATE_UNSOLICITED_NOTIFICATION_NO_MESSAGE.get(
           getToolName(), String.valueOf(notification.getResultCode()),
           notification.getOID());
    }
    else
    {
      message = INFO_PARALLEL_UPDATE_UNSOLICITED_NOTIFICATION_NO_MESSAGE.get(
           getToolName(), String.valueOf(notification.getResultCode()),
           notification.getOID(), notification.getDiagnosticMessage());
    }

    out();
    wrapOut(0, WRAP_COLUMN, message);
    out();
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
           "--hostname", "server.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--promptForBindPassword",
           "--ldifFile", "changes.ldif",
           "--rejectFile", "rejects.ldif",
           "--defaultAdd",
           "--numThreads", "10",
           "--ratePerSecond", "5000"
         },
         INFO_PARALLEL_UPDATE_EXAMPLE_DESC.get());

    return examples;
  }
}
