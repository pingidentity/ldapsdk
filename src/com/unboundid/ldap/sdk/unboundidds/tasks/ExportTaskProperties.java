/*
 * Copyright 2023-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2025 Ping Identity Corporation
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
 * Copyright (C) 2023-2025 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a set of properties that may be used in conjunction with
 * an LDIF export administrative task.
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
public final class ExportTaskProperties
{
  // Indicates whether to append the data to an existing file.
  private boolean appendToLDIF;

  // Indicates whether to compress the data.
  private boolean compress;

  // Indicates whether to encrypt the data.
  private boolean encrypt;

  // Indicates whether to sign the data.
  private boolean sign;

  // Indicates whether to generate an administrative alert if the task completes
  // with an error.
  @Nullable private Boolean alertOnError;

  // Indicates whether to generate an administrative alert when the task starts
  // running.
  @Nullable private Boolean alertOnStart;

  // Indicates whether to generate an administrative alert if the task completes
  // successfully.
  @Nullable private Boolean alertOnSuccess;

  // The time at which the task should start running.
  @Nullable private Date scheduledStartTime;

  // The action to take if any of the dependencies for this task complete
  // unsuccessfully.
  @Nullable private FailedDependencyAction failedDependencyAction;

  // The column at which to wrap long lines.
  private int wrapColumn;

  // The maximum write rate in megabytes per second.
  @Nullable private Integer maxMegabytesPerSecond;

  // The dependency IDs of any tasks on which the collect support data task
  // should depend.
  @NotNull private final List<String> dependencyIDs;

  // The set of attributes to exclude from the export.
  @NotNull private final List<String> excludeAttributes;

  // The set of base DNs to exclude from the export.
  @NotNull private final List<String> excludeBranches;

  // The set of filters to use to identify entries to exclude.
  @NotNull private final List<String> excludeFilters;

  // The set of attributes to include in the export.
  @NotNull private final List<String> includeAttributes;

  // The set of base DNs to include in the export.
  @NotNull private final List<String> includeBranches;

  // The set of filters to use to identify entries to include.
  @NotNull private final List<String> includeFilters;

  // The addresses to email whenever the task completes, regardless of success
  // or failure.
  @NotNull private final List<String> notifyOnCompletion;

  // The addresses to email if the task completes with an error.
  @NotNull private final List<String> notifyOnError;

  // The addresses to email when the task starts.
  @NotNull private final List<String> notifyOnStart;

  // The addresses to email if the task completes successfully.
  @NotNull private final List<String> notifyOnSuccess;

  // The names or DNs of the post-ldif-export task processors to invoke for
  // the export.
  @NotNull private final List<String> postExportTaskProcessors;

  // The backend ID of the backend to export.
  @NotNull private String backendID;

  // The path to a file containing the passphrase to use to generate the
  // encryption key.
  @Nullable private String encryptionPassphraseFile;

  // The identifier for the encryption settings definition to use to generate
  // the encryption key.
  @Nullable private String encryptionSettingsDefinitionID;

  // The path to the LDIF file to generate.
  @NotNull private String ldifFile;

  // The task ID to use for the collect support data task.
  @Nullable private String taskID;



  /**
   * Creates a new set of export task properties without default values for
   * all properties except those specified.
   *
   * @param  backendID  The backend ID of the backend containing the data to
   *                    export.  It must not be {@code null}.
   * @param  ldifFile   The path to the LDIF file to create.  It may be an
   *                    absolute path or a path relative to the server install
   *                    root.  It must not be {@code null}.
   */
  public ExportTaskProperties(@NotNull final String backendID,
                              @NotNull final String ldifFile)
  {
    this.backendID = backendID;
    this.ldifFile = ldifFile;

    appendToLDIF = false;
    compress = false;
    encrypt = false;
    sign = false;
    alertOnError = null;
    alertOnStart = null;
    alertOnSuccess = null;
    scheduledStartTime = null;
    failedDependencyAction = null;
    wrapColumn = -1;
    maxMegabytesPerSecond = null;
    dependencyIDs = new ArrayList<>(5);
    excludeAttributes = new ArrayList<>(5);
    excludeBranches = new ArrayList<>(5);
    excludeFilters = new ArrayList<>(5);
    includeAttributes = new ArrayList<>(5);
    includeBranches = new ArrayList<>(5);
    includeFilters = new ArrayList<>(5);
    notifyOnCompletion = new ArrayList<>(5);
    notifyOnError = new ArrayList<>(5);
    notifyOnStart = new ArrayList<>(5);
    notifyOnSuccess = new ArrayList<>(5);
    postExportTaskProcessors = new ArrayList<>(5);
    encryptionPassphraseFile = null;
    encryptionSettingsDefinitionID = null;
    taskID = null;
  }



  /**
   * Creates a new set of export task properties as a copy of the provided set
   * of properties.
   *
   * @param  properties  The export task properties that should be used to
   *                     create the new export task properties object.  It must
   *                     not be {@code null}.
   */
  public ExportTaskProperties(@NotNull final ExportTaskProperties properties)
  {
    appendToLDIF = properties.appendToLDIF;
    compress = properties.compress;
    encrypt = properties.encrypt;
    sign = properties.sign;
    alertOnError = properties.alertOnError;
    alertOnStart = properties.alertOnStart;
    alertOnSuccess = properties.alertOnSuccess;
    scheduledStartTime = properties.scheduledStartTime;
    failedDependencyAction = properties.failedDependencyAction;
    wrapColumn = properties.wrapColumn;
    maxMegabytesPerSecond = properties.maxMegabytesPerSecond;
    dependencyIDs = new ArrayList<>(properties.dependencyIDs);
    excludeAttributes = new ArrayList<>(properties.excludeAttributes);
    excludeBranches = new ArrayList<>(properties.excludeBranches);
    excludeFilters = new ArrayList<>(properties.excludeFilters);
    includeAttributes = new ArrayList<>(properties.includeAttributes);
    includeBranches = new ArrayList<>(properties.includeBranches);
    includeFilters = new ArrayList<>(properties.includeFilters);
    notifyOnCompletion = new ArrayList<>(properties.notifyOnCompletion);
    notifyOnError = new ArrayList<>(properties.notifyOnError);
    notifyOnStart = new ArrayList<>(properties.notifyOnStart);
    notifyOnSuccess = new ArrayList<>(properties.notifyOnSuccess);
    postExportTaskProcessors =
         new ArrayList<>(properties.postExportTaskProcessors);
    backendID = properties.backendID;
    encryptionPassphraseFile = properties.encryptionPassphraseFile;
    encryptionSettingsDefinitionID = properties.encryptionSettingsDefinitionID;
    ldifFile = properties.ldifFile;
    taskID = properties.taskID;
  }



  /**
   * Creates a new set of export task properties from the settings for the
   * provided task.
   *
   * @param  task  The export task to use to create the task properties.
   */
  public ExportTaskProperties(@NotNull final ExportTask task)
  {
    appendToLDIF = task.appendToLDIF();
    compress = task.compress();
    encrypt = task.encrypt();
    sign = task.sign();
    alertOnError = task.getAlertOnError();
    alertOnStart = task.getAlertOnStart();
    alertOnSuccess = task.getAlertOnSuccess();
    scheduledStartTime = task.getScheduledStartTime();
    failedDependencyAction = task.getFailedDependencyAction();
    wrapColumn = task.getWrapColumn();
    maxMegabytesPerSecond = task.getMaxMegabytesPerSecond();
    dependencyIDs = new ArrayList<>(task.getDependencyIDs());
    excludeAttributes = new ArrayList<>(task.getExcludeAttributes());
    excludeBranches = new ArrayList<>(task.getExcludeBranches());
    excludeFilters = new ArrayList<>(task.getExcludeFilters());
    includeAttributes = new ArrayList<>(task.getIncludeAttributes());
    includeBranches = new ArrayList<>(task.getIncludeBranches());
    includeFilters = new ArrayList<>(task.getIncludeFilters());
    notifyOnCompletion = new ArrayList<>(task.getNotifyOnCompletionAddresses());
    notifyOnError = new ArrayList<>(task.getNotifyOnErrorAddresses());
    notifyOnStart = new ArrayList<>(task.getNotifyOnStartAddresses());
    notifyOnSuccess = new ArrayList<>(task.getNotifyOnSuccessAddresses());
    postExportTaskProcessors =
         new ArrayList<>(task.getPostExportTaskProcessors());
    backendID = task.getBackendID();
    encryptionPassphraseFile = task.getEncryptionPassphraseFile();
    encryptionSettingsDefinitionID = task.getEncryptionSettingsDefinitionID();
    ldifFile = task.getLDIFFile();
    taskID = task.getTaskID();
  }



  /**
   * Retrieves the backend ID of the backend to be exported.
   *
   * @return  The backend ID of the backend to be exported.
   */
  @NotNull()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Specifies the backend ID of the backend to be exported.
   *
   * @param  backendID  The backend ID of the backend to be exported.  It must
   *                    not be {@code null}.
   */
  public void setBackendID(@NotNull final String backendID)
  {
    Validator.ensureNotNullWithMessage(backendID,
         "ExportTaskProperties.backendID must not be null.");

    this.backendID = backendID;
  }



  /**
   * Retrieves the path to the LDIF file to be written.
   *
   * @return  The path to the LDIF file to be written.
   */
  @NotNull()
  public String getLDIFFile()
  {
    return ldifFile;
  }



  /**
   * Specifies the path to the LDIF file to be written.
   *
   * @param  ldifFile  The path to the LDIF file to be written.  It may be an
   *                   absolute path or one that is relative to the server
   *                   root.  It must not be {@code null}.
   */
  public void setLDIFFile(@NotNull final String ldifFile)
  {
    Validator.ensureNotNullWithMessage(backendID,
         "ExportTaskProperties.ldifFile must not be null.");

    this.ldifFile = ldifFile;
  }



  /**
   * Indicates whether to append to an existing LDIF file rather than
   * overwriting it.
   *
   * @return  {@code true} if the export should append to an existing LDIF file,
   *          or {@code false} if the existing file should be overwritten.
   */
  public boolean appendToLDIF()
  {
    return appendToLDIF;
  }



  /**
   * Specifies whether to append to an existing LDIF file rather than
   * overwriting it.
   *
   * @param  appendToLDIF  Indicates whether to append to an existing LDIF file
   *                       rather than overwriting it.
   */
  public void setAppendToLDIF(final boolean appendToLDIF)
  {
    this.appendToLDIF = appendToLDIF;
  }



  /**
   * Retrieves the set of base DNs for the subtrees to include in the export.
   *
   * @return  The set of base DNs for the subtrees to include in the export, or
   *          an empty list if no include base DNs should be specified.
   */
  @NotNull()
  public List<String> getIncludeBranches()
  {
    return includeBranches;
  }



  /**
   * Specifies the set of base DNs for the subtrees to include in the export.
   *
   * @param  includeBranches  The set of base DNs for the subtrees to include in
   *                          the export.  It may be {@code null} or empty if no
   *                          include branches should be specified.
   */
  public void setIncludeBranches(@Nullable final List<String> includeBranches)
  {
    this.includeBranches.clear();
    if (includeBranches != null)
    {
      this.includeBranches.addAll(includeBranches);
    }
  }



  /**
   * Retrieves the set of base DNs for the subtrees to exclude from the export.
   *
   * @return  The set of base DNs for the subtrees to exclude from the export,
   *          or an empty list if no exclude base DNs should be specified.
   */
  @NotNull()
  public List<String> getExcludeBranches()
  {
    return excludeBranches;
  }



  /**
   * Specifies the set of base DNs for the subtrees to exclude from the export.
   *
   * @param  excludeBranches  The set of base DNs for the subtrees to exclude
   *                          from the export.  It may be {@code null} or empty
   *                          if no exclude branches should be specified.
   */
  public void setExcludeBranches(@Nullable final List<String> excludeBranches)
  {
    this.excludeBranches.clear();
    if (excludeBranches != null)
    {
      this.excludeBranches.addAll(excludeBranches);
    }
  }



  /**
   * Retrieves a set of filter strings to use to identify entries to include in
   * the export.
   *
   * @return  A set of filter strings to use to identify entries to include in
   *          the export, or an empty list if no include filters should be
   *          specified.
   */
  @NotNull()
  public List<String> getIncludeFilters()
  {
    return includeFilters;
  }



  /**
   * Specifies a set of filter strings to use to identify entries to include in
   * the export.
   *
   * @param  includeFilters  A set of filter strings to use to identify entries
   *                         to include in the export.  It may be {@code null}
   *                         or empty if no include filters should be specified.
   */
  public void setIncludeFilters(@Nullable final List<String> includeFilters)
  {
    this.includeFilters.clear();
    if (includeFilters != null)
    {
      this.includeFilters.addAll(includeFilters);
    }
  }



  /**
   * Retrieves a set of filter strings to use to identify entries to exclude
   * from the export.
   *
   * @return  A set of filter strings to use to identify entries to exclude from
   *          the export, or an empty list if no exclude filters should be
   *          specified.
   */
  @NotNull()
  public List<String> getExcludeFilters()
  {
    return excludeFilters;
  }



  /**
   * Specifies a set of filter strings to use to identify entries to exclude
   * from the export.
   *
   * @param  excludeFilters  A set of filter strings to use to identify entries
   *                         to exclude from the export.  It may be {@code null}
   *                         or empty if no exclude filters should be specified.
   */
  public void setExcludeFilters(@Nullable final List<String> excludeFilters)
  {
    this.excludeFilters.clear();
    if (excludeFilters != null)
    {
      this.excludeFilters.addAll(excludeFilters);
    }
  }



  /**
   * Retrieves the names of the attributes to include in the exported entries.
   *
   * @return  The names of the attributes to include in the exported entries, or
   *          an empty list if no include attributes should be specified.
   */
  @NotNull()
  public List<String> getIncludeAttributes()
  {
    return includeAttributes;
  }



  /**
   * Specifies the names of the attributes to include in the exported entries.
   *
   * @param  includeAttributes  The names of the attributes to include in the
   *                            exported entries.  It may be {@code null} or
   *                            empty if no include attributes should be
   *                            specified.
   */
  public void setIncludeAttributes(
                   @Nullable final List<String> includeAttributes)
  {
    this.includeAttributes.clear();
    if (includeAttributes != null)
    {
      this.includeAttributes.addAll(includeAttributes);
    }
  }



  /**
   * Retrieves the names of the attributes to exclude from the exported entries.
   *
   * @return  The names of the attributes to exclude from the exported entries,
   *          or an empty list if no exclude attributes should be specified.
   */
  @NotNull()
  public List<String> getExcludeAttributes()
  {
    return excludeAttributes;
  }



  /**
   * Specifies the names of the attributes to exclude from the exported entries.
   *
   * @param  excludeAttributes  The names of the attributes to exclude from the
   *                            exported entries.  It may be {@code null} or
   *                            empty if no exclude attributes should be
   *                            specified.
   */
  public void setExcludeAttributes(
                   @Nullable final List<String> excludeAttributes)
  {
    this.excludeAttributes.clear();
    if (excludeAttributes != null)
    {
      this.excludeAttributes.addAll(excludeAttributes);
    }
  }



  /**
   * Retrieves the column at which long lines should be wrapped.
   *
   * @return  The column at which long lines should be wrapped, or -1 if long
   *          lines should not be wrapped.
   */
  public int getWrapColumn()
  {
    return wrapColumn;
  }



  /**
   * Specifies the column at which long lines should be wrapped.
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.  It
   *                     may be less than or equal to zero if long lines should
   *                     not be wrapped.
   */
  public void setWrapColumn(final int wrapColumn)
  {
    if (wrapColumn > 0)
    {
      this.wrapColumn = wrapColumn;
    }
    else
    {
      this.wrapColumn = -1;
    }
  }



  /**
   * Indicates whether the LDIF file should be compressed.
   *
   * @return  {@code true} if the LDIF file should be compressed, or
   *          {@code false} if not.
   */
  public boolean compress()
  {
    return compress;
  }



  /**
   * Specifies whether the LDIF file should be compressed.
   *
   * @param  compress  Indicates whether the LDIF file should be compressed.
   */
  public void setCompress(final boolean compress)
  {
    this.compress = compress;
  }



  /**
   * Indicates whether the LDIF file should be encrypted.
   *
   * @return  {@code true} if the LDIF file should be encrypted, or
   *          {@code false} if not.
   */
  public boolean encrypt()
  {
    return encrypt;
  }



  /**
   * Specifies whether the LDIF file should be encrypted.
   *
   * @param  encrypt  Indicates whether the LDIF file should be encrypted.
   */
  public void setEncrypt(final boolean encrypt)
  {
    this.encrypt = encrypt;
  }



  /**
   * Retrieves the path to a file containing the passphrase to use to generate
   * the encryption key.
   *
   * @return  The path to a file containing the passphrase to use to generate
   *          the encryption key, or {@code null} if the LDIF file should not
   *          be encrypted or if it should be encrypted with a key obtained
   *          through some other means.
   */
  @Nullable()
  public String getEncryptionPassphraseFile()
  {
    return encryptionPassphraseFile;
  }



  /**
   * Specifies the path to a file containing the passphrase to use to generate
   * the encryption key.
   *
   * @param  encryptionPassphraseFile  The path to a file containing the
   *                                   passphrase to use to generate the
   *                                   encryption key.  It may be {@code null}
   *                                   if the LDIF file should not be encrypted
   *                                   or if it should be encrypted with a key
   *                                   obtained through some other means.
   */
  public void setEncryptionPassphraseFile(
                   @Nullable final String encryptionPassphraseFile)
  {
    this.encryptionPassphraseFile = encryptionPassphraseFile;
  }



  /**
   * Retrieves the ID of the encryption settings definition to use to generate
   * the encryption key.
   *
   * @return  The ID of the encryption settings definition to use to generate
   *          the encryption key, or {@code null} if the LDIF file should not be
   *          encrypted, if it should be encrypted with the server's preferred
   *          encryption settings definition, or if it should be encrypted with
   *          a key obtained through some other means.
   */
  @Nullable()
  public String getEncryptionSettingsDefinitionID()
  {
    return encryptionSettingsDefinitionID;
  }



  /**
   * Specifies the ID of the encryption settings definition to use to generate
   * the encryption key.
   *
   * @param  encryptionSettingsDefinitionID  The ID of the encryption settings
   *                                         definition to use to generate the
   *                                         encryption key.  It may be
   *                                         {@code null} if the LDIF file
   *                                         should not be encrypted, if it
   *                                         should be encrypted with the
   *                                         server's preferred encryption
   *                                         settings definition, or if it
   *                                         should be encrypted with a key
   *                                         obtained through some other means.
   */
  public void setEncryptionSettingsDefinitionID(
                   @Nullable final String encryptionSettingsDefinitionID)
  {
    this.encryptionSettingsDefinitionID = encryptionSettingsDefinitionID;
  }



  /**
   * Indicates whether the LDIF file should be cryptographically signed.
   *
   * @return  {@code true} if the LDIF file should be cryptographically signed,
   *          or {@code false} if not.
   */
  public boolean sign()
  {
    return sign;
  }



  /**
   * Specifies whether the LDIF file should be cryptographically signed.
   *
   * @param  sign  Indicates whether the LDIF file should be cryptographically
   *               signed.
   */
  public void setSign(final boolean sign)
  {
    this.sign = sign;
  }



  /**
   * Retrieves the maximum rate at which the LDIF file should be written, in
   * megabytes per second.
   *
   * @return  The maximum rate at which the LDIF file should be written, in
   *          megabytes per second, or {@code null} if no rate limiting should
   *          be used.
   */
  @Nullable()
  public Integer getMaxMegabytesPerSecond()
  {
    return maxMegabytesPerSecond;
  }



  /**
   * Specifies the maximum rate at which the LDIF file should be written, in
   * megabytes per second.
   *
   * @param  maxMegabytesPerSecond  The maximum rate at which the LDIF file
   *                                should be written, in megabytes per second.
   *                                A value of {@code null}, or one that is less
   *                                than or equal to zero, indicates that no
   *                                rate limiting should be used.
   */
  public void setMaxMegabytesPerSecond(
                   @Nullable final Integer maxMegabytesPerSecond)
  {
    if ((maxMegabytesPerSecond == null) || (maxMegabytesPerSecond <= 0))
    {
      this.maxMegabytesPerSecond = null;
    }
    else
    {
      this.maxMegabytesPerSecond = maxMegabytesPerSecond;
    }

  }



  /**
   * Retrieves a list containing the names or DNs of any post-LDIF-export task
   * processors that should be invoked for the export.
   *
   * @return  A list containing the names or DNs of any post-LDIF-export task
   *          processors that should be invoked for the export.
   */
  @NotNull()
  public List<String> getPostExportTaskProcessors()
  {
    return postExportTaskProcessors;
  }



  /**
   * Specifies a list containing the names or DNs of any post-LDIF-export task
   * processors that should be invoked for the export.
   *
   * @param  postExportTaskProcessors  A list containing the names or DNs of any
   *                                   post-LDIF-export task processors that
   *                                   should be invoked for the export.  It may
   *                                   be {@code null} or empty if no
   *                                   post-LDIF-export task processors should
   *                                   be invoked.
   */
  public void setPostExportTaskProcessors(
                   @Nullable final List<String> postExportTaskProcessors)
  {
    this.postExportTaskProcessors.clear();
    if (postExportTaskProcessors != null)
    {
      this.postExportTaskProcessors.addAll(postExportTaskProcessors);
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
    buffer.append("ExportTaskProperties(");

    appendNameValuePair(buffer, "taskID", taskID);
    appendNameValuePair(buffer, "backendID", backendID);
    appendNameValuePair(buffer, "ldifFile", ldifFile);
    appendNameValuePair(buffer, "appendToLDIF", appendToLDIF);
    appendNameValuePair(buffer, "includeBranches", includeBranches);
    appendNameValuePair(buffer, "excludeBranches", excludeBranches);
    appendNameValuePair(buffer, "includeFilters", includeFilters);
    appendNameValuePair(buffer, "excludeFilters", excludeFilters);
    appendNameValuePair(buffer, "includeAttributes", includeAttributes);
    appendNameValuePair(buffer, "excludeAttributes", excludeAttributes);
    appendNameValuePair(buffer, "wrapColumn", wrapColumn);
    appendNameValuePair(buffer, "compress", compress);
    appendNameValuePair(buffer, "encrypt", encrypt);
    appendNameValuePair(buffer, "encryptionPassphraseFile",
         encryptionPassphraseFile);
    appendNameValuePair(buffer, "encryptionSettingsDefinitionID",
         encryptionSettingsDefinitionID);
    appendNameValuePair(buffer, "sign", sign);
    appendNameValuePair(buffer, "maxMegabytesPerSecond", maxMegabytesPerSecond);
    appendNameValuePair(buffer, "postExportTaskProcessors",
         postExportTaskProcessors);
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
