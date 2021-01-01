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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.DurationArgument;



/**
 * This class defines a set of properties that may be used when creating a
 * {@link CollectSupportDataTask}.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CollectSupportDataTaskProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1424492798476859173L;



  // Indicates whether to generate an administrative alert if the task completes
  // with an error.
  @Nullable private Boolean alertOnError;

  // Indicates whether to generate an administrative alert when the task starts
  // running.
  @Nullable private Boolean alertOnStart;

  // Indicates whether to generate an administrative alert if the task completes
  // successfully.
  @Nullable private Boolean alertOnSuccess;

  // Indicates whether to include binary files in the support data archive.
  @Nullable private Boolean includeBinaryFiles;

  // Indicates whether to include expensive data in the support data archive.
  @Nullable private Boolean includeExpensiveData;

  // Indicates whether to include third-party extension source code in the
  // support data archive.
  @Nullable private Boolean includeExtensionSource;

  // Indicates whether to include a replication state dump in the support data
  // archive.
  @Nullable private Boolean includeReplicationStateDump;

  // Indicates whether to capture information sequentially rather than in
  // parallel.
  @Nullable private Boolean useSequentialMode;

  // The security level to use for data included in the support data archive.
  @Nullable private CollectSupportDataSecurityLevel securityLevel;

  // The time at which the task should start running.
  @Nullable private Date scheduledStartTime;

  // The action to take if any of the dependencies for this task complete
  // unsuccessfully.
  @Nullable private FailedDependencyAction failedDependencyAction;

  // The number of jstacks to include in the support data archive.
  @Nullable private Integer jstackCount;

  // The amount of data in kilobytes to capture from the beginning of each log
  // file.
  @Nullable private Integer logFileHeadCollectionSizeKB;

  // The amount of data in kilobytes to capture from the end of each log file.
  @Nullable private Integer logFileTailCollectionSizeKB;

  // The report count to use for sampled metrics.
  @Nullable private Integer reportCount;

  // The report interval in seconds to use for sampled metrics.
  @Nullable private Integer reportIntervalSeconds;

  // The minimum number of existing support data archives that should be
  // retained.
  @Nullable private Integer retainPreviousSupportDataArchiveCount;

  // The dependency IDs of any tasks on which the collect support data task
  // should depend.
  @NotNull private final List<String> dependencyIDs;

  // The addresses to email whenever the task completes, regardless of success
  // or failure.
  @NotNull private final List<String> notifyOnCompletion;

  // The addresses to email if the task completes with an error.
  @NotNull private final List<String> notifyOnError;

  // The addresses to email when the task starts.
  @NotNull private final List<String> notifyOnStart;

  // The addresses to email if the task completes successfully.
  @NotNull private final List<String> notifyOnSuccess;

  // A comment to include in the support data archive.
  @Nullable private String comment;

  // The path to the encryption passphrase file.
  @Nullable private String encryptionPassphraseFile;

  // A string representation of the log duration to capture.
  @Nullable private String logDuration;

  // The path to which the support data archive should be written.
  @Nullable private String outputPath;

  // The minimum age for existing support data archives that should be retained.
  @Nullable private String retainPreviousSupportDataArchiveAge;

  // The task ID to use for the collect support data task.
  @Nullable private String taskID;



  /**
   * Creates a new set of collect support data task properties without any of
   * the properties set (so that the server will use default values for all of
   * them).
   */
  public CollectSupportDataTaskProperties()
  {
    alertOnError = null;
    alertOnStart = null;
    alertOnSuccess = null;
    includeBinaryFiles = null;
    includeExpensiveData = null;
    includeExtensionSource = null;
    includeReplicationStateDump = null;
    useSequentialMode = null;
    securityLevel = null;
    scheduledStartTime = null;
    failedDependencyAction = null;
    jstackCount = null;
    logFileHeadCollectionSizeKB = null;
    logFileTailCollectionSizeKB = null;
    reportCount = null;
    reportIntervalSeconds = null;
    retainPreviousSupportDataArchiveCount = null;
    dependencyIDs = new ArrayList<>(5);
    notifyOnCompletion = new ArrayList<>(5);
    notifyOnError = new ArrayList<>(5);
    notifyOnStart = new ArrayList<>(5);
    notifyOnSuccess = new ArrayList<>(5);
    comment = null;
    encryptionPassphraseFile = null;
    logDuration = null;
    outputPath = null;
    retainPreviousSupportDataArchiveAge = null;
    taskID = null;
  }



  /**
   * Creates a new set of collect support data task properties as a copy of the
   * provided properties.
   *
   * @param  properties  The collect support data task properties to duplicate.
   */
  public CollectSupportDataTaskProperties(
              @NotNull final CollectSupportDataTaskProperties properties)
  {
    alertOnError = properties.getAlertOnError();
    alertOnStart = properties.getAlertOnStart();
    alertOnSuccess = properties.getAlertOnSuccess();
    includeBinaryFiles = properties.getIncludeBinaryFiles();
    includeExpensiveData = properties.getIncludeExpensiveData();
    includeExtensionSource = properties.getIncludeExtensionSource();
    includeReplicationStateDump = properties.getIncludeReplicationStateDump();
    useSequentialMode = properties.getUseSequentialMode();
    securityLevel = properties.getSecurityLevel();
    scheduledStartTime = properties.getScheduledStartTime();
    failedDependencyAction = properties.getFailedDependencyAction();
    jstackCount = properties.getJStackCount();
    logFileHeadCollectionSizeKB = properties.getLogFileHeadCollectionSizeKB();
    logFileTailCollectionSizeKB = properties.getLogFileTailCollectionSizeKB();
    reportCount = properties.getReportCount();
    reportIntervalSeconds = properties.getReportIntervalSeconds();
    retainPreviousSupportDataArchiveCount =
         properties.getRetainPreviousSupportDataArchiveCount();
    dependencyIDs = new ArrayList<>(properties.getDependencyIDs());
    notifyOnCompletion = new ArrayList<>(properties.getNotifyOnCompletion());
    notifyOnError = new ArrayList<>(properties.getNotifyOnError());
    notifyOnStart = new ArrayList<>(properties.getNotifyOnStart());
    notifyOnSuccess = new ArrayList<>(properties.getNotifyOnSuccess());
    comment = properties.getComment();
    encryptionPassphraseFile = properties.getEncryptionPassphraseFile();
    logDuration = properties.getLogDuration();
    outputPath = properties.getOutputPath();
    retainPreviousSupportDataArchiveAge =
         properties.getRetainPreviousSupportDataArchiveAge();
    taskID = properties.getTaskID();
  }



  /**
   * Creates a new set of collect support data task properties set from the
   * provided task instance.
   *
   * @param  task  The collect support data task instance from which the
   *               properties should be set.
   */
  public CollectSupportDataTaskProperties(
              @NotNull final CollectSupportDataTask task)
  {
    alertOnError = task.getAlertOnError();
    alertOnStart = task.getAlertOnStart();
    alertOnSuccess = task.getAlertOnSuccess();
    includeBinaryFiles = task.getIncludeBinaryFiles();
    includeExpensiveData = task.getIncludeExpensiveData();
    includeExtensionSource = task.getIncludeExtensionSource();
    includeReplicationStateDump = task.getIncludeReplicationStateDump();
    useSequentialMode = task.getUseSequentialMode();
    securityLevel = task.getSecurityLevel();
    scheduledStartTime = task.getScheduledStartTime();
    failedDependencyAction = task.getFailedDependencyAction();
    jstackCount = task.getJStackCount();
    logFileHeadCollectionSizeKB = task.getLogFileHeadCollectionSizeKB();
    logFileTailCollectionSizeKB = task.getLogFileTailCollectionSizeKB();
    reportCount = task.getReportCount();
    reportIntervalSeconds = task.getReportIntervalSeconds();
    retainPreviousSupportDataArchiveCount =
         task.getRetainPreviousSupportDataArchiveCount();
    dependencyIDs = new ArrayList<>(task.getDependencyIDs());
    notifyOnCompletion = new ArrayList<>(task.getNotifyOnCompletionAddresses());
    notifyOnError = new ArrayList<>(task.getNotifyOnErrorAddresses());
    notifyOnStart = new ArrayList<>(task.getNotifyOnStartAddresses());
    notifyOnSuccess = new ArrayList<>(task.getNotifyOnSuccessAddresses());
    comment = task.getComment();
    encryptionPassphraseFile = task.getEncryptionPassphraseFile();
    logDuration = task.getLogDuration();
    outputPath = task.getOutputPath();
    retainPreviousSupportDataArchiveAge =
         task.getRetainPreviousSupportDataArchiveAge();
    taskID = task.getTaskID();
  }



  /**
   * Retrieves the path on the server filesystem to which the support data
   * archive should be written.
   *
   * @return  The path on the server filesystem to which the support data
   *          archive should be written, or {@code null} if no value has been
   *          specified for the property.
   */
  @Nullable()
  public String getOutputPath()
  {
    return outputPath;
  }



  /**
   * Specifies the path on the server filesystem to which the support data '
   * archive should be written.  If this is provided, then the value may be
   * one of the following:
   * <UL>
   *   <LI>If the path refers to a file that exists, then the file will be
   *       overwritten with the new support data archive.</LI>
   *   <LI>If the path refers to a directory that exists, then the support data
   *       archive will be written into that directory with a name generated
   *       by the server.</LI>
   *   <LI>If the path refers to a file that does not exist, then its parent
   *       directory must exist, and the support data archive will be written
   *       with the specified path and name.</LI>
   * </UL>
   *
   * @param  outputPath  The path on the server filesystem to which the support
   *                     data archive should be written.  It may be {@code null}
   *                     if the server should choose the path and name for the
   *                     output file.
   */
  public void setOutputPath(@Nullable final String outputPath)
  {
    this.outputPath = outputPath;
  }



  /**
   * Retrieves the path on the server filesystem to a file that contains the
   * passphrase to use to encrypt the support data archive.
   *
   * @return  The path on the server filesystem to a file that contains the
   *          passphrase to use to encrypt the support data archive, or
   *          {@code null} if no value has been specified for the property, and
   *          the support data archive should not be encrypted.
   */
  @Nullable()
  public String getEncryptionPassphraseFile()
  {
    return encryptionPassphraseFile;
  }



  /**
   * Specifies the path on the server filesystem to a file that contains the
   * passphrase to use to encrypt the support data archive.  If this is
   * provided, then this must refer to a file that exists and that contains
   * exactly one line whose entire content is the desired encryption passphrase.
   *
   * @param  encryptionPassphraseFile  The path on the server filesystem to a
   *                                   file that contains the passphrase to use
   *                                   to encrypt the support data archive.  It
   *                                   may be {@code null} if the support data
   *                                   archive should not be encrypted.
   */
  public void setEncryptionPassphraseFile(
                   @Nullable final String encryptionPassphraseFile)
  {
    this.encryptionPassphraseFile = encryptionPassphraseFile;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include data that is potentially expensive to collect and
   * could affect the performance or responsiveness of the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include data that is potentially expensive to collect,
   *          or {@code null} if the property should not be specified when the
   *          task is created (in which case the server will use a default
   *          behavior of excluding expensive data).
   */
  @Nullable()
  public Boolean getIncludeExpensiveData()
  {
    return includeExpensiveData;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive may include data that is potentially expensive to collect and could
   * affect the performance or responsiveness of the server.
   *
   * @param  includeExpensiveData  The value of a flag that indicates whether
   *                               the support data archive may include data
   *                               that is potentially expensive to collect.  It
   *                               may be {@code null} if the flag should not be
   *                               specified when the task is created (in which
   *                               case the server will use a default behavior
   *                               of excluding expensive data).
   */
  public void setIncludeExpensiveData(
                   @Nullable final Boolean includeExpensiveData)
  {
    this.includeExpensiveData = includeExpensiveData;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include a replication state dump, which may be several
   * megabytes in size.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include a replication state dump, or {@code null} if
   *          the property should not be specified when the task is created (in
   *          which case the server will use a default behavior of excluding the
   *          state dump).
   */
  @Nullable()
  public Boolean getIncludeReplicationStateDump()
  {
    return includeReplicationStateDump;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive may include a replication state dump, which may be several
   * megabytes in size.
   *
   * @param  includeReplicationStateDump  The value of a flag that indicates
   *                                      whether the support data archive may
   *                                      include a replication state dump.  It
   *                                      may be {@code null} if the flag should
   *                                      not be specified when the task is
   *                                      created (in which case the server will
   *                                      use a default behavior of excluding
   *                                      the state dump).
   */
  public void setIncludeReplicationStateDump(
                   @Nullable final Boolean includeReplicationStateDump)
  {
    this.includeReplicationStateDump = includeReplicationStateDump;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include binary files.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include binary files, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default behavior of excluding binary files).
   */
  @Nullable()
  public Boolean getIncludeBinaryFiles()
  {
    return includeBinaryFiles;
  }



  /**
   * Specifies the value of a flag that that indicates whether the support data
   * archive may include binary files.
   *
   * @param  includeBinaryFiles  The value of a flag that indicates whether the
   *                             support data archive may include binary files.
   *                             It may be {@code null} if the property should
   *                             not be specified when the task is created (in
   *                             which case the server will use a default
   *                             behavior of excluding binary files).
   */
  public void setIncludeBinaryFiles(@Nullable final Boolean includeBinaryFiles)
  {
    this.includeBinaryFiles = includeBinaryFiles;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive should include source code (if available) for any third-party
   * extensions installed in the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive should include source code (if available) for any
   *          third-party extensions installed in the server, or {@code null} if
   *          the property should not be specified when the task is created (in
   *          which case the server will use a default behavior of excluding
   *          extension source code).
   */
  @Nullable()
  public Boolean getIncludeExtensionSource()
  {
    return includeExtensionSource;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive should include source code (if available) for any third-party
   * extensions installed in the server.
   *
   * @param  includeExtensionSource  The value of a flag that indicates whether
   *                                 the support data archive should include
   *                                 source code (if available) for any
   *                                 third-party extensions in the server.  It
   *                                 may be {@code null} if the property should
   *                                 not be specified when the task is
   *                                 created (in which case the server will use
   *                                 a default behavior of excluding extension
   *                                 source code).
   */
  public void setIncludeExtensionSource(
                   @Nullable final Boolean includeExtensionSource)
  {
    this.includeExtensionSource = includeExtensionSource;
  }



  /**
   * Retrieves the value of a flag that indicates whether the server should
   * collect items for the support data archive in sequential mode rather than
   * in parallel.  Collecting data in sequential mode may reduce the amount of
   * memory consumed during the collection process, but it will take longer to
   * complete.
   *
   * @return  The value of a flag that indicates whether the server should
   *          collect items for the support data archive in sequential mode
   *          rather than in parallel, or {@code null} if the property should
   *          not be specified when the task is created (in which case the
   *          server will default to capturing data in parallel).
   */
  @Nullable()
  public Boolean getUseSequentialMode()
  {
    return useSequentialMode;
  }



  /**
   * Specifies the value of a flag that indicates whether the server should
   * collect items for the support data archive in sequential mode rather than
   * in parallel.  Collecting data in sequential mode may reduce the amount of
   * memory consumed during the collection process, but it will take longer to
   * complete.
   *
   * @param  useSequentialMode  The value of a flag that indicates whether the
   *                            server should collect items for the support data
   *                            archive in sequential mode rather than in
   *                            parallel.  It may be {@code null} if the
   *                            property should not be specified when the task
   *                            is created (in which case the server will
   *                            default to capturing data in parallel).
   */
  public void setUseSequentialMode(@Nullable final Boolean useSequentialMode)
  {
    this.useSequentialMode = useSequentialMode;
  }



  /**
   * Retrieves the security level that should be used to indicate which data
   * should be obscured, redacted, or omitted from the support data archive.
   *
   * @return  The security level that should be used when creating the support
   *          data archive, or {@code null} if the property should not be
   *          specified when the task is created (in which case the server will
   *          use a default security level).
   */
  @Nullable()
  public CollectSupportDataSecurityLevel getSecurityLevel()
  {
    return securityLevel;
  }



  /**
   * Specifies the security level that should be used to indicate which data
   * should be obscured, redacted, or omitted from the support data archive.
   *
   * @param  securityLevel  The security level that should be used when creating
   *                        the support data archive.  It may be {@code null} if
   *                        the property should not be specified when the task
   *                        is created (in which case the server will use a
   *                        default security level).
   */
  public void setSecurityLevel(
       @Nullable final CollectSupportDataSecurityLevel securityLevel)

  {
    this.securityLevel = securityLevel;
  }



  /**
   * Retrieves the number of intervals that should be captured from tools that
   * use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The number of intervals that should be captured from tools that
   *          use interval-based sampling, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default report count).
   */
  @Nullable()
  public Integer getReportCount()
  {
    return reportCount;
  }



  /**
   * Specifies the number of intervals that should be captured form tools that
   * use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @param  reportCount  The number of intervals that should be captured from
   *                      tools that use interval-based sampling.  The value
   *                      must not be negative, but it may be zero to indicate
   *                      that no intervals should be captured.  It may be
   *                      {@code null} if the property should not be specified
   *                      when the task is created (in which case the server
   *                      will use a default report count).
   */
  public void setReportCount(@Nullable final Integer reportCount)
  {
    this.reportCount = reportCount;
  }



  /**
   * Retrieves the interval duration in seconds that should be used for tools
   * that use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The interval duration in seconds that should be used for tools
   *          that use interval-based sampling, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default report interval).
   */
  @Nullable()
  public Integer getReportIntervalSeconds()
  {
    return reportIntervalSeconds;
  }



  /**
   * Specifies the interval duration in seconds that should be used for tools
   * that use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @param  reportIntervalSeconds  The interval duration in seconds that should
   *                                be used for tools that use interval-based
   *                                sampling.  The value must be greater than or
   *                                equal to one.  It may be {@code null} if the
   *                                property should not be specified when the
   *                                task is created (in which case the server
   *                                will use a default report count).
   */
  public void setReportIntervalSeconds(
                   @Nullable final Integer reportIntervalSeconds)
  {
    this.reportIntervalSeconds = reportIntervalSeconds;
  }



  /**
   * Retrieves the number of times that the jstack utility should be invoked to
   * obtain stack traces from all threads in the server.
   *
   * @return  The number of times that the jstack utility should be invoked to
   *          obtain stack traces from all threads in the server, or
   *          {@code null} if the property should not be specified when the task
   *          is created (in which case the server will use a default count).
   */
  @Nullable()
  public Integer getJStackCount()
  {
    return jstackCount;
  }



  /**
   * Specifies the number of times that the jstack utility should be invoked to
   * obtain stack traces from all threads in the server.
   *
   * @param  jstackCount  The number of times that the jstack utility should be
   *                      invoked to obtain stack traces from all threads in the
   *                      server.  The value must not be negative, but it may be
   *                      zero to indicate that the jstack utility should not be
   *                      invoked.  It may be {@code null} if the property
   *                      should not be specified when the task is created (in
   *                      which case the server will use a default count).
   */
  public void setJStackCount(@Nullable final Integer jstackCount)
  {
    this.jstackCount = jstackCount;
  }



  /**
   * Retrieves a string representation of the duration (up until the time that
   * the collect support data task is invoked) of log content that should be
   * included in the support data archive.
   *
   * @return  A string representation of the duration of log content that should
   *          be included in the support data archive, or {@code null} if the
   *          property should not be specified when the task is created (in
   *          which case the server will use a default behavior for selecting
   *          the amount of log content to include).
   */
  @Nullable()
  public String getLogDuration()
  {
    return logDuration;
  }



  /**
   * Retrieves a parsed value of the log duration in milliseconds.
   *
   * @return  A parsed value of the log duration in milliseconds or {@code null}
   *          if no log duration is set.
   *
   * @throws  TaskException  If the log duration value cannot be parsed as a
   *                         valid duration.
   */
  @Nullable()
  public Long getLogDurationMillis()
         throws TaskException
  {
    if (logDuration == null)
    {
      return null;
    }

    try
    {
      return DurationArgument.parseDuration(logDuration, TimeUnit.MILLISECONDS);
    }
    catch (final ArgumentException e)
    {
      Debug.debugException(e);
      throw new TaskException(e.getMessage(), e);
    }
  }



  /**
   * Specifies the string representation of the duration (up until the time that
   * the collect support data task is invoked) of log content that should be
   * included in the support data archive.
   * <BR><BR>
   * The string representation of the duration should be specified as
   * an integer followed by a time unit, where the unit may be one of
   * millisecond, second, minute, hour, day, or week (or one of their plurals).
   * For example, "5 minutes" or "1 hour".
   *
   * @param  logDuration  The string representation of the duration of log
   *                      content that should be included in the support data
   *                      archive.  It may be {@code null} if the property
   *                      should not be specified when the task is created (in
   *                      which case the server will determine an appropriate
   *                      amount of log content to include).
   *
   * @throws  TaskException  If the provided string representation cannot be
   *                         parsed as a valid duration.
   */
  public void setLogDuration(@Nullable final String logDuration)
         throws TaskException
  {
    if (logDuration == null)
    {
      this.logDuration = null;
    }
    else
    {
      try
      {
        DurationArgument.parseDuration(logDuration, TimeUnit.MILLISECONDS);
        this.logDuration = logDuration;
      }
      catch (final ArgumentException e)
      {
        Debug.debugException(e);
        throw new TaskException(e.getMessage(), e);
      }
    }
  }



  /**
   * Specifies the duration in milliseconds (up until the time that the collect
   * support data task is invoked) of log content that should be included in the
   * support data archive.
   *
   * @param  logDurationMillis  The duration in milliseconds of log content that
   *                            should be included in the support data archive.
   *                            The value must be greater than zero.  It may be
   *                            {@code null} if the property should not be
   *                            specified when the task is created (in which
   *                            case the server will determine an appropriate
   *                            amount of log content to include).
   */
  public void setLogDurationMillis(@Nullable final Long logDurationMillis)
  {
    if (logDurationMillis == null)
    {
      logDuration = null;
    }
    else
    {
      logDuration = DurationArgument.nanosToDuration(
           TimeUnit.MILLISECONDS.toNanos(logDurationMillis));
    }
  }



  /**
   * Retrieves the amount of data in kilobytes to capture from the beginning of
   * each log file that should be included in the support data archive.
   *
   * @return  The amount of data in kilobytes to capture from the beginning of
   *          each log file that should be included in the support data archive,
   *          or {@code null} if the property should not be specified when the
   *          task is created (in which case the server will determine an
   *          appropriate amount of log content to include).
   */
  @Nullable()
  public Integer getLogFileHeadCollectionSizeKB()
  {
    return logFileHeadCollectionSizeKB;
  }



  /**
   * Specifies the amount of data in kilobytes to capture from the beginning of
   * each log file that should be included in the support data archive.
   *
   * @param  logFileHeadCollectionSizeKB  The amount of data in kilobytes to
   *                                      capture from the beginning of each log
   *                                      file that should be included in the
   *                                      support data archive.  This may be
   *                                      {@code null} if the property should
   *                                      not be specified when the task is
   *                                      created (in which case the server will
   *                                      determine an appropriate amount of log
   *                                      content to include).
   */
  public void setLogFileHeadCollectionSizeKB(
                   @Nullable final Integer logFileHeadCollectionSizeKB)
  {
    this.logFileHeadCollectionSizeKB = logFileHeadCollectionSizeKB;
  }



  /**
   * Retrieves the amount of data in kilobytes to capture from the end of each
   * log file that should be included in the support data archive.
   *
   * @return  The amount of data in kilobytes to capture from the end of each
   *          log file that should be included in the support data archive, or
   *          {@code null} if the property should not be specified when the task
   *          is created (in which case the server will determine an
   *          appropriate amount of log content to include).
   */
  @Nullable()
  public Integer getLogFileTailCollectionSizeKB()
  {
    return logFileTailCollectionSizeKB;
  }



  /**
   * Specifies the amount of data in kilobytes to capture from the end of each
   * log file that should be included in the support data archive.
   *
   * @param  logFileTailCollectionSizeKB  The amount of data in kilobytes to
   *                                      capture from the end of each log file
   *                                      that should be included in the
   *                                      support data archive.  This may be
   *                                      {@code null} if the property should
   *                                      not be specified when the task is
   *                                      created (in which case the server will
   *                                      determine an appropriate amount of log
   *                                      content to include).
   */
  public void setLogFileTailCollectionSizeKB(
                   @Nullable final Integer logFileTailCollectionSizeKB)
  {
    this.logFileTailCollectionSizeKB = logFileTailCollectionSizeKB;
  }



  /**
   * Retrieves an additional comment that should be included in the support data
   * archive.
   *
   * @return  An additional comment that should be included in the support data
   *          archive, or {@code null} if no comment should be included.
   */
  @Nullable()
  public String getComment()
  {
    return comment;
  }



  /**
   * Specifies an additional comment that should be included in the support data
   * archive.
   *
   * @param  comment  An additional comment that should be included in the
   *                  support data archive.  It may be {@code null} if no
   *                  additional comment should be included.
   */
  public void setComment(@Nullable final String comment)
  {
    this.comment = comment;
  }



  /**
   * Retrieves the minimum number of existing support data archives that should
   * be retained.
   *
   * @return  The minimum number of existing support data archives that should
   *          be retained, or {@code null} if there is no minimum retain count.
   */
  @Nullable()
  public Integer getRetainPreviousSupportDataArchiveCount()
  {
    return retainPreviousSupportDataArchiveCount;
  }



  /**
   * Specifies the minimum number of existing support data archives that should
   * be retained.
   * <BR><BR>
   * Note that if an output path is specified, then a retain count or retain age
   * may only be used if that output path specifies a directory rather than a
   * file, so that the file name will be generated by the server, and only
   * archive files in that directory with names that conform to the
   * server-generated pattern may be removed.
   * <BR><BR>
   * If neither a retain count nor a retain age is specified, then no existing
   * support data archives will be removed.  If both are specified, then any
   * existing archive that is outside the criteria for either will be removed.
   *
   * @param  retainPreviousSupportDataArchiveCount
   *              The minimum number of existing support data archives that
   *              should be retained.  A value of zero indicates that only the
   *              new support data archive should be retained, and any other
   *              preexisting archives may be removed.  It may be {@code null}
   *              if only the age of existing archives should be considered (if
   *              a retain age is specified), or if no existing support data
   *              archives should be removed (if no retain age is specified).
   */
  public void setRetainPreviousSupportDataArchiveCount(
       @Nullable final Integer retainPreviousSupportDataArchiveCount)
  {
    this.retainPreviousSupportDataArchiveCount =
         retainPreviousSupportDataArchiveCount;
  }



  /**
   * Retrieves the minimum age of existing support data archives that should be
   * retained.
   *
   * @return  The minimum age of existing support data archives that should
   *          be retained, or {@code null} if there is no minimum retain age.
   */
  @Nullable()
  public String getRetainPreviousSupportDataArchiveAge()
  {
    return retainPreviousSupportDataArchiveAge;
  }



  /**
   * Retrieves a parsed value of the retain previous support data archive age in
   * milliseconds.
   *
   * @return  A parsed value of the retain previous support data archive age in
   *          milliseconds or {@code null} if no retain age is set.
   *
   * @throws  TaskException  If the retain age value cannot be parsed as a valid
   *                         duration.
   */
  @Nullable()
  public Long getRetainPreviousSupportDataArchiveAgeMillis()
         throws TaskException
  {
    if (retainPreviousSupportDataArchiveAge == null)
    {
      return null;
    }

    try
    {
      return DurationArgument.parseDuration(
           retainPreviousSupportDataArchiveAge, TimeUnit.MILLISECONDS);
    }
    catch (final ArgumentException e)
    {
      Debug.debugException(e);
      throw new TaskException(e.getMessage(), e);
    }
  }



  /**
   * Specifies the minimum age of existing support data archives that should be
   * retained.
   * <BR><BR>
   * The string representation of the duration should be specified as an integer
   * followed by a time unit, where the unit may be one of millisecond, second,
   * minute, hour, day, or week (or one of their plurals).  For example, "5
   * minutes" or "1 hour".
   * <BR><BR>
   * Note that if an output path is specified, then a retain count or retain age
   * may only be used if that output path specifies a directory rather than a
   * file, so that the file name will be generated by the server, and only
   * archive files in that directory with names that conform to the
   * server-generated pattern may be removed.
   * <BR><BR>
   * If neither a retain count nor a retain age is specified, then no existing
   * support data archives will be removed.  If both are specified, then any
   * existing archive that is outside the criteria for either will be removed.
   *
   * @param  retainPreviousSupportDataArchiveAge
   *              The minimum age of existing support data archives that
   *              should be retained.  Any existing support data archives that
   *              are older than this may be removed.  It may be {@code null}
   *              if only the number of existing archives should be considered
   *              (if a retain count is specified), or if no existing support
   *              data archives should be removed (if no retain count is
   *              specified).
   *
   * @throws  TaskException  If the provided string representation cannot be
   *                         parsed as a valid duration.
   */
  public void setRetainPreviousSupportDataArchiveAge(
                   @Nullable final String retainPreviousSupportDataArchiveAge)
         throws TaskException
  {
    if (retainPreviousSupportDataArchiveAge == null)
    {
      this.retainPreviousSupportDataArchiveAge = null;
    }
    else
    {
      try
      {
        DurationArgument.parseDuration(retainPreviousSupportDataArchiveAge,
             TimeUnit.MILLISECONDS);
        this.retainPreviousSupportDataArchiveAge =
             retainPreviousSupportDataArchiveAge;
      }
      catch (final ArgumentException e)
      {
        Debug.debugException(e);
        throw new TaskException(e.getMessage(), e);
      }
    }
  }



  /**
   * Specifies the minimum age in milliseconds of existing support data
   * archives that should be retained.
   * <BR><BR>
   * Note that if an output path is specified, then a retain count or retain age
   * may only be used if that output path specifies a directory rather than a
   * file, so that the file name will be generated by the server, and only
   * archive files in that directory with names that conform to the
   * server-generated pattern may be removed.
   * <BR><BR>
   * If neither a retain count nor a retain age is specified, then no existing
   * support data archives will be removed.  If both are specified, then any
   * existing archive that is outside the criteria for either will be removed.
   *
   * @param  retainPreviousSupportDataArchiveAgeMillis
   *              The minimum age in milliseconds of existing support data
   *              archives that should be retained.  Any existing support data
   *              archives that are older than this may be removed.  It may be
   *              {@code null} if only the number of existing archives should be
   *              considered (if a retain count is specified), or if no existing
   *              support data archives should be removed (if no retain count is
   *              specified).
   */
  public void setRetainPreviousSupportDataArchiveAgeMillis(
       @Nullable final Long retainPreviousSupportDataArchiveAgeMillis)
  {
    if (retainPreviousSupportDataArchiveAgeMillis == null)
    {
      retainPreviousSupportDataArchiveAge = null;
    }
    else
    {
      retainPreviousSupportDataArchiveAge = DurationArgument.nanosToDuration(
           TimeUnit.MILLISECONDS.toNanos(
                retainPreviousSupportDataArchiveAgeMillis));
    }
  }



  /**
   * Retrieves the task ID that should be used for the task.
   *
   * @return  The task ID that should be used for the task, or {@code null} if a
   *          random UUID should be generated for use as the task ID.
   */
  @Nullable()
  public String getTaskID()
  {
    return taskID;
  }



  /**
   *Specifies the task ID that should be used for the task.
   *
   * @param  taskID  The task ID that should be used for the task.  It may be
   *                 {@code null} if a random UUID should be generated for use
   *                 as the task ID.
   */
  public void setTaskID(@Nullable final String taskID)
  {
    this.taskID = taskID;
  }



  /**
   * Retrieves the earliest time that the task should be eligible to start
   * running.
   *
   * @return  The earliest time that the task should be eligible to start
   *          running, or {@code null} if the task should be eligible to start
   *          immediately (or as soon as all of its dependencies have been
   *          satisfied).
   */
  @Nullable()
  public Date getScheduledStartTime()
  {
    return scheduledStartTime;
  }



  /**
   * Specifies the earliest time that the task should be eligible to start
   * running.
   *
   * @param  scheduledStartTime  The earliest time that the task should be
   *                             eligible to start running.  It may be
   *                             {@code null} if the task should be eligible to
   *                             start immediately (or as soon as all of its
   *                             dependencies have been satisfied).
   */
  public void setScheduledStartTime(@Nullable final Date scheduledStartTime)
  {
    this.scheduledStartTime = scheduledStartTime;
  }



  /**
   * Retrieves the task IDs for any tasks that must complete before the new
   * collect support data task will be eligible to start running.
   *
   * @return  The task IDs for any tasks that must complete before the new
   *          collect support data task will be eligible to start running, or
   *          an empty list if the new task should not depend on any other
   *          tasks.
   */
  @NotNull()
  public List<String> getDependencyIDs()
  {
    return new ArrayList<>(dependencyIDs);
  }



  /**
   * Specifies the task IDs for any tasks that must complete before the new
   * collect support data task will be eligible to start running.
   *
   * @param  dependencyIDs  The task IDs for any tasks that must complete before
   *                        the new collect support data task will be eligible
   *                        to start running.  It may be {@code null} or empty
   *                        if the new task should not depend on any other
   *                        tasks.
   */
  public void setDependencyIDs(@Nullable final List<String> dependencyIDs)
  {
    this.dependencyIDs.clear();
    if (dependencyIDs != null)
    {
      this.dependencyIDs.addAll(dependencyIDs);
    }
  }



  /**
   * Retrieves the action that the server should take if any of the tasks on
   * which the new task depends did not complete successfully.
   *
   * @return  The action that the server should take if any of the tasks on
   *          which the new task depends did not complete successfully, or
   *          {@code null} if the property should not be specified when creating
   *          the task (and the server should choose an appropriate failed
   *          dependency action).
   */
  @Nullable()
  public FailedDependencyAction getFailedDependencyAction()
  {
    return failedDependencyAction;
  }



  /**
   * Specifies the action that the server should take if any of the tasks on
   * which the new task depends did not complete successfully.
   *
   * @param  failedDependencyAction  The action that the server should take if
   *                                 any of the tasks on which the new task
   *                                 depends did not complete successfully.  It
   *                                 may be {@code null} if the property should
   *                                 not be specified when creating the task
   *                                 (and the server should choose an
   *                                 appropriate failed dependency action).
   */
  public void setFailedDependencyAction(
       @Nullable final FailedDependencyAction failedDependencyAction)
  {
    this.failedDependencyAction = failedDependencyAction;
  }



  /**
   * Retrieves the addresses to email whenever the task starts running.
   *
   * @return  The addresses to email whenever the task starts running, or an
   *          empty list if no email notification should be sent when starting
   *          the task.
   */
  @NotNull()
  public List<String> getNotifyOnStart()
  {
    return new ArrayList<>(notifyOnStart);
  }



  /**
   * Specifies the addresses to email whenever the task starts running.
   *
   * @param  notifyOnStart  The addresses to email whenever the task starts
   *                        running.  It amy be {@code null} or empty if no
   *                        email notification should be sent when starting the
   *                        task.
   */
  public void setNotifyOnStart(@Nullable final List<String> notifyOnStart)
  {
    this.notifyOnStart.clear();
    if (notifyOnStart != null)
    {
      this.notifyOnStart.addAll(notifyOnStart);
    }
  }



  /**
   * Retrieves the addresses to email whenever the task completes, regardless of
   * its success or failure.
   *
   * @return  The addresses to email whenever the task completes, or an
   *          empty list if no email notification should be sent when the task
   *          completes.
   */
  @NotNull()
  public List<String> getNotifyOnCompletion()
  {
    return new ArrayList<>(notifyOnCompletion);
  }



  /**
   * Specifies the addresses to email whenever the task completes, regardless of
   * its success or failure.
   *
   * @param  notifyOnCompletion  The addresses to email whenever the task
   *                             completes.  It amy be {@code null} or empty if
   *                             no email notification should be sent when the
   *                             task completes.
   */
  public void setNotifyOnCompletion(
                   @Nullable final List<String> notifyOnCompletion)
  {
    this.notifyOnCompletion.clear();
    if (notifyOnCompletion != null)
    {
      this.notifyOnCompletion.addAll(notifyOnCompletion);
    }
  }



  /**
   * Retrieves the addresses to email if the task completes successfully.
   *
   * @return  The addresses to email if the task completes successfully, or an
   *          empty list if no email notification should be sent on successful
   *          completion.
   */
  @NotNull()
  public List<String> getNotifyOnSuccess()
  {
    return new ArrayList<>(notifyOnSuccess);
  }



  /**
   * Specifies the addresses to email if the task completes successfully.
   *
   * @param  notifyOnSuccess  The addresses to email if the task completes
   *                          successfully.  It amy be {@code null} or empty if
   *                          no email notification should be sent on
   *                          successful completion.
   */
  public void setNotifyOnSuccess(@Nullable final List<String> notifyOnSuccess)
  {
    this.notifyOnSuccess.clear();
    if (notifyOnSuccess != null)
    {
      this.notifyOnSuccess.addAll(notifyOnSuccess);
    }
  }



  /**
   * Retrieves the addresses to email if the task does not complete
   * successfully.
   *
   * @return  The addresses to email if the task does not complete successfully,
   *          or an empty list if no email notification should be sent on an
   *          unsuccessful completion.
   */
  @NotNull()
  public List<String> getNotifyOnError()
  {
    return new ArrayList<>(notifyOnError);
  }



  /**
   * Specifies the addresses to email if the task does not complete
   * successfully.
   *
   * @param  notifyOnError  The addresses to email if the task does not complete
   *                        successfully.  It amy be {@code null} or empty if
   *                        no email notification should be sent on an
   *                        unsuccessful completion.
   */
  public void setNotifyOnError(@Nullable final List<String> notifyOnError)
  {
    this.notifyOnError.clear();
    if (notifyOnError != null)
    {
      this.notifyOnError.addAll(notifyOnError);
    }
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification when the task starts running.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification when the task starts running,
   *          or {@code null} if the property should not be specified when the
   *          task is created (and the server will default to not sending any
   *          alert).
   */
  @Nullable()
  public Boolean getAlertOnStart()
  {
    return alertOnStart;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification when the task starts running.
   *
   * @param  alertOnStart  The flag that indicates whether the server should
   *                       send an administrative alert notification when the
   *                       task starts running,  It may be {@code null} if the
   *                       property should not be specified when the task is
   *                       created (and the server will default to not sending
   *                       any alert).
   */
  public void setAlertOnStart(@Nullable final Boolean alertOnStart)
  {
    this.alertOnStart = alertOnStart;
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification if the task completes successfully.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification if the task completes
   *          successfully, or {@code null} if the property should not be
   *          specified when the task is created (and the server will default to
   *          not sending any alert).
   */
  @Nullable()
  public Boolean getAlertOnSuccess()
  {
    return alertOnSuccess;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification if the task completes successfully.
   *
   * @param  alertOnSuccess  The flag that indicates whether the server should
   *                         send an administrative alert notification if the
   *                         task completes successfully,  It may be
   *                         {@code null} if the property should not be
   *                         specified when the task is created (and the server
   *                         will default to not sending any alert).
   */
  public void setAlertOnSuccess(@Nullable final Boolean alertOnSuccess)
  {
    this.alertOnSuccess = alertOnSuccess;
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification if the task does not complete
   * successfully.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification if the task does not complete
   *          successfully, or {@code null} if the property should not be
   *          specified when the task is created (and the server will default to
   *          not sending any alert).
   */
  @Nullable()
  public Boolean getAlertOnError()
  {
    return alertOnError;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification if the task does not complete
   * successfully.
   *
   * @param  alertOnError  The flag that indicates whether the server should
   *                       send an administrative alert notification if the task
   *                       does not complete successfully,  It may be
   *                       {@code null} if the property should not be specified
   *                       when the task is created (and the server will default
   *                       to not sending any alert).
   */
  public void setAlertOnError(@Nullable final Boolean alertOnError)
  {
    this.alertOnError = alertOnError;
  }



  /**
   * Retrieves a string representation of this collect support data task
   * properties object.
   *
   * @return  A string representation of this collect support data task
   *          properties object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this collect support data task
   * properties object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation will be
   *                 appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CollectSupportDataArchiveProperties(");

    appendNameValuePair(buffer, "taskID", taskID);
    appendNameValuePair(buffer, "outputPath", outputPath);
    appendNameValuePair(buffer, "encryptionPassphraseFile",
         encryptionPassphraseFile);
    appendNameValuePair(buffer, "includeExpensiveData", includeExpensiveData);
    appendNameValuePair(buffer, "includeReplicationStateDump",
         includeReplicationStateDump);
    appendNameValuePair(buffer, "includeBinaryFiles", includeBinaryFiles);
    appendNameValuePair(buffer, "includeExtensionSource",
         includeExtensionSource);
    appendNameValuePair(buffer, "securityLevel", securityLevel);
    appendNameValuePair(buffer, "useSequentialMode", useSequentialMode);
    appendNameValuePair(buffer, "reportCount", reportCount);
    appendNameValuePair(buffer, "reportIntervalSeconds", reportIntervalSeconds);
    appendNameValuePair(buffer, "jstackCount", jstackCount);
    appendNameValuePair(buffer, "logDuration", logDuration);
    appendNameValuePair(buffer, "logFileHeadCollectionSizeKB",
         logFileHeadCollectionSizeKB);
    appendNameValuePair(buffer, "logFileTailCollectionSizeKB",
         logFileTailCollectionSizeKB);
    appendNameValuePair(buffer, "comment", comment);
    appendNameValuePair(buffer, "retainPreviousSupportDataArchiveCount",
         retainPreviousSupportDataArchiveCount);
    appendNameValuePair(buffer, "retainPreviousSupportDataArchiveAge",
         retainPreviousSupportDataArchiveAge);
    appendNameValuePair(buffer, "scheduledStartTime", scheduledStartTime);
    appendNameValuePair(buffer, "dependencyIDs", dependencyIDs);
    appendNameValuePair(buffer, "failedDependencyAction",
         failedDependencyAction);
    appendNameValuePair(buffer, "notifyOnStart", notifyOnStart);
    appendNameValuePair(buffer, "notifyOnCompletion", notifyOnCompletion);
    appendNameValuePair(buffer, "notifyOnSuccess", notifyOnSuccess);
    appendNameValuePair(buffer, "notifyOnError", notifyOnError);
    appendNameValuePair(buffer, "alertOnStart", alertOnStart);
    appendNameValuePair(buffer, "alertOnSuccess", alertOnSuccess);
    appendNameValuePair(buffer, "alertOnError", alertOnError);

    buffer.append(')');
  }



  /**
   * Appends a name-value pair to the provided buffer, if the value is
   * non-{@code null}.
   *
   * @param  buffer  The buffer to which the name-value pair should be appended.
   * @param  name    The name to be used.  It must not be {@code null}.
   * @param  value   The value to be used.  It may be {@code null} if there is
   *                 no value for the property.
   */
  private static void appendNameValuePair(@NotNull final StringBuilder buffer,
                                          @NotNull final String name,
                                          @Nullable final Object value)
  {
    if (value == null)
    {
      return;
    }

    if ((buffer.length() > 0) &&
         (buffer.charAt(buffer.length() - 1) != '('))
    {
      buffer.append(", ");
    }

    buffer.append(name);
    buffer.append("='");
    buffer.append(value);
    buffer.append('\'');
  }



  /**
   * Appends a name-value pair to the provided buffer, if the value is
   * non-{@code null}.
   *
   * @param  buffer   The buffer to which the name-value pair should be
   *                  appended.
   * @param  name     The name to be used.  It must not be {@code null}.
   * @param  values   The list of values to be used.  It may be {@code null} or
   *                  empty if there are no values for the property.
   */
  private static void appendNameValuePair(@NotNull final StringBuilder buffer,
                                          @NotNull final String name,
                                          @Nullable final List<String> values)
  {
    if ((values == null) || values.isEmpty())
    {
      return;
    }

    if ((buffer.length() > 0) &&
         (buffer.charAt(buffer.length() - 1) != '('))
    {
      buffer.append(", ");
    }

    buffer.append(name);
    buffer.append("={ ");

    final Iterator<String> iterator = values.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append('}');
  }
}
