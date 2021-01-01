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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to export the
 * contents of a backend to LDIF.
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
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>The backend ID for the backend from which the data is to be exported.
 *       It must be provided when scheduling a task of this type.</LI>
 *   <LI>The path (on the server system) and name of the LDIF file to be
 *       written.  It must be provided when scheduling a task of this type.</LI>
 *   <LI>A flag that indicates whether to append to any existing file or to
 *       overwrite it.</LI>
 *   <LI>An optional list of base DNs for branches that should be included in
 *       the export.</LI>
 *   <LI>An optional list of base DNs for branches that should be excluded from
 *       the export.</LI>
 *   <LI>An optional list of filters that may be used to determine whether an
 *       entry should be included in the export.</LI>
 *   <LI>An optional list of filters that may be used to determine whether an
 *       entry should be excluded from the export.</LI>
 *   <LI>An optional list of attributes that should be included in entries that
 *       are exported.</LI>
 *   <LI>An optional list of attributes that should be excluded form entries
 *       that are exported.</LI>
 *   <LI>An integer value that specifies the column at which long lines should
 *       be wrapped.  A value less than or equal to zero indicates that no
 *       wrapping should be performed.</LI>
 *   <LI>A flag that indicates whether to compress the LDIF data as it is
 *       written.</LI>
 *   <LI>A flag that indicates whether to encrypt the LDIF data as it is
 *       written.</LI>
 *   <LI>A flag that indicates whether to generate a signature for the LDIF data
 *       as it is written.</LI>
 *   <LI>The path to a file containing a passphrase to use to generate the
 *       encryption key.</LI>
 *   <LI>The ID of the encryption settings definition to use to generate the
 *       encryption key.</LI>
 *   <LI>The maximum rate in megabytes per second at which the LDIF file should
 *       be written.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExportTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the export
   * task.
   */
  @NotNull static final String EXPORT_TASK_CLASS =
       "com.unboundid.directory.server.tasks.ExportTask";



  /**
   * The name of the attribute used to indicate whether to append to an existing
   * file.
   */
  @NotNull private static final String ATTR_APPEND_TO_LDIF =
       "ds-task-export-append-to-ldif";



  /**
   * The name of the attribute used to specify the backend ID of the backend to
   * export.
   */
  @NotNull private static final String ATTR_BACKEND_ID =
       "ds-task-export-backend-id";



  /**
   * The name of the attribute used to indicate whether the exported LDIF should
   * be compressed as it is written.
   */
  @NotNull private static final String ATTR_COMPRESS =
       "ds-task-export-compress-ldif";



  /**
   * The name of the attribute used to indicate whether the exported LDIF should
   * be encrypted as it is written.
   */
  @NotNull private static final String ATTR_ENCRYPT =
       "ds-task-export-encrypt-ldif";



  /**
   * The name of the attribute used to specify the path to a file that contains
   * the passphrase to use to generate the encryption key.
   */
  @NotNull private static final String ATTR_ENCRYPTION_PASSPHRASE_FILE =
       "ds-task-export-encryption-passphrase-file";



  /**
   * The name of the attribute used to specify the path to a file that contains
   * the ID of the encryption settings definition to use to generate the
   * encryption key.
   */
  @NotNull private static final String ATTR_ENCRYPTION_SETTINGS_DEFINITION_ID =
       "ds-task-export-encryption-settings-definition-id";



  /**
   * The name of the attribute used to specify the attributes to exclude from
   * the export.
   */
  @NotNull private static final String ATTR_EXCLUDE_ATTRIBUTE =
       "ds-task-export-exclude-attribute";



  /**
   * The name of the attribute used to specify the base DNs to exclude from the
   * export.
   */
  @NotNull private static final String ATTR_EXCLUDE_BRANCH =
       "ds-task-export-exclude-branch";



  /**
   * The name of the attribute used to specify the filters to use to identify
   * entries to exclude from the export.
   */
  @NotNull private static final String ATTR_EXCLUDE_FILTER =
       "ds-task-export-exclude-filter";



  /**
   * The name of the attribute used to specify the attributes to include in the
   * export.
   */
  @NotNull private static final String ATTR_INCLUDE_ATTRIBUTE =
       "ds-task-export-include-attribute";



  /**
   * The name of the attribute used to specify the base DNs to include in the
   * export.
   */
  @NotNull private static final String ATTR_INCLUDE_BRANCH =
       "ds-task-export-include-branch";



  /**
   * The name of the attribute used to specify the filters to use to identify
   * entries to include in the export.
   */
  @NotNull private static final String ATTR_INCLUDE_FILTER =
       "ds-task-export-include-filter";



  /**
   * The name of the attribute used to specify the path to the LDIF file to be
   * written.
   */
  @NotNull private static final String ATTR_LDIF_FILE =
       "ds-task-export-ldif-file";



  /**
   * The name of the attribute used to specify the maximum LDIF write rate in
   * megabytes per second.
   */
  @NotNull private static final String ATTR_MAX_MEGABYTES_PER_SECOND =
       "ds-task-export-max-megabytes-per-second";



  /**
   * The name of the attribute used to indicate whether the exported LDIF should
   * include a signed hash of the contents.
   */
  @NotNull private static final String ATTR_SIGN = "ds-task-export-sign-hash";



  /**
   * The name of the attribute used to specify the column at which to wrap long
   * lines in the export.
   */
  @NotNull private static final String ATTR_WRAP_COLUMN =
       "ds-task-export-wrap-column";



  /**
   * The name of the object class used in export task entries.
   */
  @NotNull private static final String OC_EXPORT_TASK = "ds-task-export";



  /**
   * The task property for the backend ID.
   */
  @NotNull private static final TaskProperty PROPERTY_BACKEND_ID =
       new TaskProperty(ATTR_BACKEND_ID, INFO_DISPLAY_NAME_BACKEND_ID.get(),
                        INFO_DESCRIPTION_BACKEND_ID_EXPORT.get(), String.class,
                        true, false, false);



  /**
   * The task property for the LDIF file.
   */
  @NotNull private static final TaskProperty PROPERTY_LDIF_FILE =
       new TaskProperty(ATTR_LDIF_FILE, INFO_DISPLAY_NAME_LDIF_FILE.get(),
                        INFO_DESCRIPTION_LDIF_FILE_EXPORT.get(), String.class,
                        true, false, false);



  /**
   * The task property for the append to LDIF flag.
   */
  @NotNull private static final TaskProperty PROPERTY_APPEND_TO_LDIF =
       new TaskProperty(ATTR_APPEND_TO_LDIF,
                        INFO_DISPLAY_NAME_APPEND_TO_LDIF.get(),
                        INFO_DESCRIPTION_APPEND_TO_LDIF.get(), Boolean.class,
                        false, false, true);



  /**
   * The task property for the include branches.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_BRANCH =
       new TaskProperty(ATTR_INCLUDE_BRANCH,
                        INFO_DISPLAY_NAME_INCLUDE_BRANCH.get(),
                        INFO_DESCRIPTION_INCLUDE_BRANCH_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude branches.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_BRANCH =
       new TaskProperty(ATTR_EXCLUDE_BRANCH,
                        INFO_DISPLAY_NAME_EXCLUDE_BRANCH.get(),
                        INFO_DESCRIPTION_EXCLUDE_BRANCH_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the include filters.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_FILTER =
       new TaskProperty(ATTR_INCLUDE_FILTER,
                        INFO_DISPLAY_NAME_INCLUDE_FILTER.get(),
                        INFO_DESCRIPTION_INCLUDE_FILTER_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude filters.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_FILTER =
       new TaskProperty(ATTR_EXCLUDE_FILTER,
                        INFO_DISPLAY_NAME_EXCLUDE_FILTER.get(),
                        INFO_DESCRIPTION_EXCLUDE_FILTER_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the include attributes.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_ATTRIBUTE =
       new TaskProperty(ATTR_INCLUDE_ATTRIBUTE,
                        INFO_DISPLAY_NAME_INCLUDE_ATTRIBUTE.get(),
                        INFO_DESCRIPTION_INCLUDE_ATTRIBUTE_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude attributes.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_ATTRIBUTE =
       new TaskProperty(ATTR_EXCLUDE_ATTRIBUTE,
                        INFO_DISPLAY_NAME_EXCLUDE_ATTRIBUTE.get(),
                        INFO_DESCRIPTION_EXCLUDE_ATTRIBUTE_EXPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the wrap column.
   */
  @NotNull private static final TaskProperty PROPERTY_WRAP_COLUMN =
       new TaskProperty(ATTR_WRAP_COLUMN, INFO_DISPLAY_NAME_WRAP_COLUMN.get(),
                        INFO_DESCRIPTION_WRAP_COLUMN.get(), Long.class, false,
                        false, true);



  /**
   * The task property for the compress flag.
   */
  @NotNull private static final TaskProperty PROPERTY_COMPRESS =
       new TaskProperty(ATTR_COMPRESS, INFO_DISPLAY_NAME_COMPRESS.get(),
                        INFO_DESCRIPTION_COMPRESS_EXPORT.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property for the encrypt flag.
   */
  @NotNull private static final TaskProperty PROPERTY_ENCRYPT =
       new TaskProperty(ATTR_ENCRYPT, INFO_DISPLAY_NAME_ENCRYPT.get(),
                        INFO_DESCRIPTION_ENCRYPT_EXPORT.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the encryption passphrase file.
   */
  @NotNull private static final TaskProperty
       PROPERTY_ENCRYPTION_PASSPHRASE_FILE = new TaskProperty(
            ATTR_ENCRYPTION_PASSPHRASE_FILE,
            INFO_DISPLAY_NAME_ENCRYPTION_PASSPHRASE_FILE.get(),
            INFO_DESCRIPTION_ENCRYPTION_PASSPHRASE_FILE.get(),
            String.class, false, false, true);



  /**
   * The task property that will be used for the encryption settings definition
   * ID.
   */
  @NotNull private static final TaskProperty
       PROPERTY_ENCRYPTION_SETTINGS_DEFINITION_ID = new TaskProperty(
            ATTR_ENCRYPTION_SETTINGS_DEFINITION_ID,
            INFO_DISPLAY_NAME_ENCRYPTION_SETTINGS_DEFINITION_ID.get(),
            INFO_DESCRIPTION_ENCRYPTION_SETTINGS_DEFINITION_ID.get(),
            String.class, false, false, true);



  /**
   * The task property for the sign flag.
   */
  @NotNull private static final TaskProperty PROPERTY_SIGN =
       new TaskProperty(ATTR_SIGN, INFO_DISPLAY_NAME_SIGN.get(),
                        INFO_DESCRIPTION_SIGN_EXPORT.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the maximum write rate in megabytes
   * per second.
   */
  @NotNull private static final TaskProperty PROPERTY_MAX_MEGABYTES_PER_SECOND =
       new TaskProperty(ATTR_MAX_MEGABYTES_PER_SECOND,
            INFO_DISPLAY_NAME_EXPORT_MAX_MEGABYTES_PER_SECOND.get(),
            INFO_DESCRIPTION_EXPORT_MAX_MEGABYTES_PER_SECOND.get(),
            Long.class, false, false, true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6807534587873728959L;



  // Indicates whether to append the data to an existing file.
  private final boolean appendToLDIF;

  // Indicates whether to compress the data.
  private final boolean compress;

  // Indicates whether to encrypt the data.
  private final boolean encrypt;

  // Indicates whether to sign the data.
  private final boolean sign;

  // The column at which to wrap long lines.
  private final int wrapColumn;

  // The maximum write rate in megabytes per second.
  @Nullable private final Integer maxMegabytesPerSecond;

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

  // The backend ID of the backend to export.
  @NotNull private final String backendID;

  // The path to a file containing the passphrase to use to generate the
  // encryption key.
  @Nullable private final String encryptionPassphraseFile;

  // The identifier for the encryption settings definition to use to generate
  // the encryption key.
  @Nullable private final String encryptionSettingsDefinitionID;

  // The path to the LDIF file to generate.
  @NotNull private final String ldifFile;



  /**
   * Creates a new uninitialized export task instance which should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public ExportTask()
  {
    appendToLDIF = false;
    compress = false;
    encrypt = false;
    sign = false;
    wrapColumn = -1;
    maxMegabytesPerSecond = null;
    encryptionPassphraseFile = null;
    encryptionSettingsDefinitionID = null;
    excludeAttributes = null;
    excludeBranches = null;
    excludeFilters = null;
    includeAttributes = null;
    includeBranches = null;
    includeFilters = null;
    backendID = null;
    ldifFile = null;
  }



  /**
   * Creates a new export task with the provided information.
   *
   * @param  taskID     The task ID to use for this task.  If it is {@code null}
   *                    then a UUID will be generated for use as the task ID.
   * @param  backendID  The backend ID of the backend containing the data to
   *                    export.  It must not be {@code null}.
   * @param  ldifFile   The path to the LDIF file to create.  It may be an
   *                    absolute path or a path relative to the server install
   *                    root.  It must not be {@code null}.
   */
  public ExportTask(@Nullable final String taskID,
                    @NotNull final String backendID,
                    @NotNull final String ldifFile)
  {
    this(taskID, backendID, ldifFile, false, null, null, null, null, null, null,
         -1, false, false, false, null, null, null, null, null);
  }



  /**
   * Creates a new export task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  backendID               The backend ID of the backend to be
   *                                 exported.  It must not be {@code null}.
   * @param  ldifFile                The path to the LDIF file to be written.
   *                                 It may be an absolute path or one that is
   *                                 relative to the server root.  It must not
   *                                 be {@code null}.
   * @param  appendToLDIF            Indicates whether to an append to any
   *                                 existing file rather than overwriting it.
   * @param  includeBranches         The set of base DNs of entries to include
   *                                 in the export.  It may be {@code null} or
   *                                 empty if no entries should be excluded
   *                                 based on their location.
   * @param  excludeBranches         The set of base DNs of entries to exclude
   *                                 from the export.  It may be {@code null} or
   *                                 empty if no entries should be excluded
   *                                 based on their location.
   * @param  includeFilters          The set of filters to use to match entries
   *                                 that should be included in the export.  It
   *                                 may be {@code null} or empty if no entries
   *                                 should be excluded based on their content.
   * @param  excludeFilters          The set of filters to use to match entries
   *                                 that should be excluded from the export.
   *                                 It may be {@code null} or empty if no
   *                                 entries should be excluded based on their
   *                                 content.
   * @param  includeAttributes       The set of attributes that should be
   *                                 included in exported entries.  It may be
   *                                 {@code null} or empty if all attributes
   *                                 should be included.
   * @param  excludeAttributes       The set of attributes that should be
   *                                 excluded from exported entries.  It may be
   *                                 {@code null} or empty if no attributes
   *                                 should be excluded.
   * @param  wrapColumn              The column at which long lines should be
   *                                 wrapped.  It may be less than or equal to
   *                                 zero to indicate that long lines should not
   *                                 be wrapped.
   * @param  compress                Indicates whether the LDIF data should be
   *                                 compressed as it is written.
   * @param  encrypt                 Indicates whether the LDIF data should be
   *                                 encrypted as it is written.
   * @param  sign                    Indicates whether to include a signed hash
   *                                 of the content in the exported data.
   * @param  scheduledStartTime      The time that this task should start
   *                                 running.
   * @param  dependencyIDs           The list of task IDs that will be required
   *                                 to complete before this task will be
   *                                 eligible to start.
   * @param  failedDependencyAction  Indicates what action should be taken if
   *                                 any of the dependencies for this task do
   *                                 not complete successfully.
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   */
  public ExportTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @NotNull final String ldifFile,
              final boolean appendToLDIF,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final int wrapColumn,
              final boolean compress,
              final boolean encrypt,
              final boolean sign,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, backendID, ldifFile, appendToLDIF, includeBranches,
         excludeBranches, includeFilters, excludeFilters, includeAttributes,
         excludeAttributes, wrapColumn, compress, encrypt, null, null, sign,
         null, scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnCompletion, notifyOnError);
  }



  /**
   * Creates a new export task with the provided information.
   *
   * @param  taskID                          The task ID to use for this task.
   *                                         If it is {@code null} then a UUID
   *                                         will be generated for use as the
   *                                         task ID.
   * @param  backendID                       The backend ID of the backend to be
   *                                         exported.  It must not be
   *                                         {@code null}.
   * @param  ldifFile                        The path to the LDIF file to be
   *                                         written.  It may be an absolute
   *                                         path or one that is relative to the
   *                                         server root.  It must not be
   *                                         {@code null}.
   * @param  appendToLDIF                    Indicates whether to an append to
   *                                         any existing file rather than
   *                                         overwriting it.
   * @param  includeBranches                 The set of base DNs of entries to
   *                                         include in the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         location.
   * @param  excludeBranches                 The set of base DNs of entries to
   *                                         exclude from the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         location.
   * @param  includeFilters                  The set of filters to use to match
   *                                         entries that should be included in
   *                                         the export.  It may be {@code null}
   *                                         or empty if no entries should be
   *                                         excluded based on their content.
   * @param  excludeFilters                  The set of filters to use to match
   *                                         entries that should be excluded
   *                                         from the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         content.
   * @param  includeAttributes               The set of attributes that should
   *                                         be included in exported entries.
   *                                         It may be {@code null} or empty if
   *                                         all attributes should be included.
   * @param  excludeAttributes               The set of attributes that should
   *                                         be excluded from exported entries.
   *                                         It may be {@code null} or empty if
   *                                         no attributes should be excluded.
   * @param  wrapColumn                      The column at which long lines
   *                                         should be wrapped.  It may be less
   *                                         than or equal to zero to indicate
   *                                         that long lines should not be
   *                                         wrapped.
   * @param  compress                        Indicates whether the LDIF data
   *                                         should be compressed as it is
   *                                         written.
   * @param  encrypt                         Indicates whether the LDIF data
   *                                         should be encrypted as it is
   *                                         written.
   * @param  encryptionPassphraseFile        The path to a file containing the
   *                                         passphrase to use to generate the
   *                                         encryption key.  It amy be
   *                                         {@code null} if the LDIF file is
   *                                         not to be encrypted, or if the key
   *                                         should be obtained in some other
   *                                         way.
   * @param  encryptionSettingsDefinitionID  The ID of the encryption settings
   *                                         definition use to generate the
   *                                         encryption key.  It may be
   *                                         {@code null} if the LDIF file is
   *                                         not to be encrypted, or if the key
   *                                         should be obtained in some other
   *                                         way.
   * @param  sign                            Indicates whether to include a
   *                                         signed hash of the content in the
   *                                         exported data.
   * @param  maxMegabytesPerSecond           The maximum rate in megabytes per
   *                                         second at which the LDIF file
   *                                         should be written.
   * @param  scheduledStartTime              The time that this task should
   *                                         start running.
   * @param  dependencyIDs                   The list of task IDs that will be
   *                                         required to complete before this
   *                                         task will be eligible to start.
   * @param  failedDependencyAction          Indicates what action should be
   *                                         taken if any of the dependencies
   *                                         for this task do not complete
   *                                         successfully.
   * @param  notifyOnCompletion              The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         when this task completes.
   * @param  notifyOnError                   The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         if this task does not complete
   *                                         successfully.
   */
  public ExportTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @NotNull final String ldifFile,
              final boolean appendToLDIF,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final int wrapColumn,
              final boolean compress, final boolean encrypt,
              @Nullable final String encryptionPassphraseFile,
              @Nullable final String encryptionSettingsDefinitionID,
              final boolean sign,
              @Nullable final Integer maxMegabytesPerSecond,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, backendID, ldifFile, appendToLDIF, includeBranches,
         excludeBranches, includeFilters, excludeFilters, includeAttributes,
         excludeAttributes, wrapColumn, compress, encrypt,
         encryptionPassphraseFile, encryptionSettingsDefinitionID, sign,
         maxMegabytesPerSecond, scheduledStartTime, dependencyIDs,
         failedDependencyAction, null, notifyOnCompletion, null,
         notifyOnError, null, null, null);
  }



  /**
   * Creates a new export task with the provided information.
   *
   * @param  taskID                          The task ID to use for this task.
   *                                         If it is {@code null} then a UUID
   *                                         will be generated for use as the
   *                                         task ID.
   * @param  backendID                       The backend ID of the backend to be
   *                                         exported.  It must not be
   *                                         {@code null}.
   * @param  ldifFile                        The path to the LDIF file to be
   *                                         written.  It may be an absolute
   *                                         path or one that is relative to the
   *                                         server root.  It must not be
   *                                         {@code null}.
   * @param  appendToLDIF                    Indicates whether to an append to
   *                                         any existing file rather than
   *                                         overwriting it.
   * @param  includeBranches                 The set of base DNs of entries to
   *                                         include in the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         location.
   * @param  excludeBranches                 The set of base DNs of entries to
   *                                         exclude from the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         location.
   * @param  includeFilters                  The set of filters to use to match
   *                                         entries that should be included in
   *                                         the export.  It may be {@code null}
   *                                         or empty if no entries should be
   *                                         excluded based on their content.
   * @param  excludeFilters                  The set of filters to use to match
   *                                         entries that should be excluded
   *                                         from the export.  It may be
   *                                         {@code null} or empty if no entries
   *                                         should be excluded based on their
   *                                         content.
   * @param  includeAttributes               The set of attributes that should
   *                                         be included in exported entries.
   *                                         It may be {@code null} or empty if
   *                                         all attributes should be included.
   * @param  excludeAttributes               The set of attributes that should
   *                                         be excluded from exported entries.
   *                                         It may be {@code null} or empty if
   *                                         no attributes should be excluded.
   * @param  wrapColumn                      The column at which long lines
   *                                         should be wrapped.  It may be less
   *                                         than or equal to zero to indicate
   *                                         that long lines should not be
   *                                         wrapped.
   * @param  compress                        Indicates whether the LDIF data
   *                                         should be compressed as it is
   *                                         written.
   * @param  encrypt                         Indicates whether the LDIF data
   *                                         should be encrypted as it is
   *                                         written.
   * @param  encryptionPassphraseFile        The path to a file containing the
   *                                         passphrase to use to generate the
   *                                         encryption key.  It amy be
   *                                         {@code null} if the LDIF file is
   *                                         not to be encrypted, or if the key
   *                                         should be obtained in some other
   *                                         way.
   * @param  encryptionSettingsDefinitionID  The ID of the encryption settings
   *                                         definition use to generate the
   *                                         encryption key.  It may be
   *                                         {@code null} if the LDIF file is
   *                                         not to be encrypted, or if the key
   *                                         should be obtained in some other
   *                                         way.
   * @param  sign                            Indicates whether to include a
   *                                         signed hash of the content in the
   *                                         exported data.
   * @param  maxMegabytesPerSecond           The maximum rate in megabytes per
   *                                         second at which the LDIF file
   *                                         should be written.
   * @param  scheduledStartTime              The time that this task should
   *                                         start running.
   * @param  dependencyIDs                   The list of task IDs that will be
   *                                         required to complete before this
   *                                         task will be eligible to start.
   * @param  failedDependencyAction          Indicates what action should be
   *                                         taken if any of the dependencies
   *                                         for this task do not complete
   *                                         successfully.
   * @param  notifyOnStart                   The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         when this task starts running.
   * @param  notifyOnCompletion              The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         when this task completes.
   * @param  notifyOnSuccess                 The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         if this task completes
   *                                         successfully.
   * @param  notifyOnError                   The list of e-mail addresses of
   *                                         individuals that should be notified
   *                                         if this task does not complete
   *                                         successfully.
   * @param  alertOnStart                    Indicates whether the server should
   *                                         send an alert notification when
   *                                         this task starts.
   * @param  alertOnSuccess                  Indicates whether the server should
   *                                         send an alert notification if this
   *                                         task completes successfully.
   * @param  alertOnError                    Indicates whether the server should
   *                                         send an alert notification if this
   *                                         task fails to complete
   *                                         successfully.
   */
  public ExportTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @NotNull final String ldifFile,
              final boolean appendToLDIF,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final int wrapColumn,
              final boolean compress, final boolean encrypt,
              @Nullable final String encryptionPassphraseFile,
              @Nullable final String encryptionSettingsDefinitionID,
              final boolean sign,
              @Nullable final Integer maxMegabytesPerSecond,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnStart,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnSuccess,
              @Nullable final List<String> notifyOnError,
              @Nullable final Boolean alertOnStart,
              @Nullable final Boolean alertOnSuccess,
              @Nullable final Boolean alertOnError)
  {
    super(taskID, EXPORT_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    Validator.ensureNotNull(backendID, ldifFile);

    this.backendID = backendID;
    this.ldifFile = ldifFile;
    this.appendToLDIF = appendToLDIF;
    this.wrapColumn = wrapColumn;
    this.compress = compress;
    this.encrypt = encrypt;
    this.encryptionPassphraseFile = encryptionPassphraseFile;
    this.encryptionSettingsDefinitionID = encryptionSettingsDefinitionID;
    this.sign = sign;
    this.maxMegabytesPerSecond = maxMegabytesPerSecond;

    if (includeBranches == null)
    {
      this.includeBranches = Collections.emptyList();
    }
    else
    {
      this.includeBranches = Collections.unmodifiableList(includeBranches);
    }

    if (excludeBranches == null)
    {
      this.excludeBranches = Collections.emptyList();
    }
    else
    {
      this.excludeBranches = Collections.unmodifiableList(excludeBranches);
    }

    if (includeFilters == null)
    {
      this.includeFilters = Collections.emptyList();
    }
    else
    {
      this.includeFilters = Collections.unmodifiableList(includeFilters);
    }

    if (excludeFilters == null)
    {
      this.excludeFilters = Collections.emptyList();
    }
    else
    {
      this.excludeFilters = Collections.unmodifiableList(excludeFilters);
    }

    if (includeAttributes == null)
    {
      this.includeAttributes = Collections.emptyList();
    }
    else
    {
      this.includeAttributes = Collections.unmodifiableList(includeAttributes);
    }

    if (excludeAttributes == null)
    {
      this.excludeAttributes = Collections.emptyList();
    }
    else
    {
      this.excludeAttributes = Collections.unmodifiableList(excludeAttributes);
    }
  }



  /**
   * Creates a new export task from the provided entry.
   *
   * @param  entry  The entry to use to create this export task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as an export
   *                         task entry.
   */
  public ExportTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the backend ID.  It must be present.
    backendID = entry.getAttributeValue(ATTR_BACKEND_ID);
    if (backendID == null)
    {
      throw new TaskException(ERR_EXPORT_TASK_NO_BACKEND_ID.get(
                                   getTaskEntryDN()));
    }


    // Get the LDIF file path.  It must be present.
    ldifFile = entry.getAttributeValue(ATTR_LDIF_FILE);
    if (ldifFile == null)
    {
      throw new TaskException(ERR_EXPORT_TASK_NO_LDIF_FILE.get(
                                   getTaskEntryDN()));
    }


    // Get the appendLDIF flag.  It may be absent.
    appendToLDIF = parseBooleanValue(entry, ATTR_APPEND_TO_LDIF, false);


    // Get the list of include branches.  It may be absent.
    includeBranches = parseStringList(entry, ATTR_INCLUDE_BRANCH);


    // Get the list of exclude branches.  It may be absent.
    excludeBranches = parseStringList(entry, ATTR_EXCLUDE_BRANCH);


    // Get the list of include filters.  It may be absent.
    includeFilters = parseStringList(entry, ATTR_INCLUDE_FILTER);


    // Get the list of exclude filters.  It may be absent.
    excludeFilters = parseStringList(entry, ATTR_EXCLUDE_FILTER);


    // Get the list of include attributes.  It may be absent.
    includeAttributes = parseStringList(entry, ATTR_INCLUDE_ATTRIBUTE);


    // Get the list of exclude attributes.  It may be absent.
    excludeAttributes = parseStringList(entry, ATTR_EXCLUDE_ATTRIBUTE);


    // Get the wrap column.  It may be absent.
    final String wrapStr = entry.getAttributeValue(ATTR_WRAP_COLUMN);
    if (wrapStr == null)
    {
      wrapColumn = -1;
    }
    else
    {
      try
      {
        wrapColumn = Integer.parseInt(wrapStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new TaskException(ERR_EXPORT_TASK_CANNOT_PARSE_WRAP_COLUMN.get(
                                     getTaskEntryDN(), wrapStr), e);
      }
    }


    // Get the compress flag.  It may be absent.
    compress = parseBooleanValue(entry, ATTR_COMPRESS, false);


    // Get the encrypt flag.  It may be absent.
    encrypt = parseBooleanValue(entry, ATTR_ENCRYPT, false);


    // Get the path to the encryption passphrase file.  It may be absent.
    encryptionPassphraseFile =
         entry.getAttributeValue(ATTR_ENCRYPTION_PASSPHRASE_FILE);


    // Get the encryption settings definition ID.  It may be absent.
    encryptionSettingsDefinitionID =
         entry.getAttributeValue(ATTR_ENCRYPTION_SETTINGS_DEFINITION_ID);


    // Get the sign flag.  It may be absent.
    sign = parseBooleanValue(entry, ATTR_SIGN, false);


    // Get the maximum write rate in megabytes per second.  It may be absent.
    maxMegabytesPerSecond =
         entry.getAttributeValueAsInteger(ATTR_MAX_MEGABYTES_PER_SECOND);
  }



  /**
   * Creates a new export task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid export task.
   */
  public ExportTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(EXPORT_TASK_CLASS, properties);

    boolean  a         = false;
    boolean  c         = false;
    boolean  e         = false;
    boolean  s         = false;
    Integer  maxMB     = null;
    long     w         = 0;
    String   b         = null;
    String   encID     = null;
    String   encPWFile = null;
    String   l         = null;
    String[] eA        = StaticUtils.NO_STRINGS;
    String[] eB        = StaticUtils.NO_STRINGS;
    String[] eF        = StaticUtils.NO_STRINGS;
    String[] iA        = StaticUtils.NO_STRINGS;
    String[] iB        = StaticUtils.NO_STRINGS;
    String[] iF        = StaticUtils.NO_STRINGS;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BACKEND_ID))
      {
        b = parseString(p, values, b);
      }
      else if (attrName.equalsIgnoreCase(ATTR_LDIF_FILE))
      {
        l = parseString(p, values, l);
      }
      else if (attrName.equalsIgnoreCase(ATTR_APPEND_TO_LDIF))
      {
        a = parseBoolean(p, values, a);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_BRANCH))
      {
        iB = parseStrings(p, values, iB);
      }
      else if (attrName.equalsIgnoreCase(ATTR_EXCLUDE_BRANCH))
      {
        eB = parseStrings(p, values, eB);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_FILTER))
      {
        iF = parseStrings(p, values, iF);
      }
      else if (attrName.equalsIgnoreCase(ATTR_EXCLUDE_FILTER))
      {
        eF = parseStrings(p, values, eF);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_ATTRIBUTE))
      {
        iA = parseStrings(p, values, iA);
      }
      else if (attrName.equalsIgnoreCase(ATTR_EXCLUDE_ATTRIBUTE))
      {
        eA = parseStrings(p, values, eA);
      }
      else if (attrName.equalsIgnoreCase(ATTR_WRAP_COLUMN))
      {
        w = parseLong(p, values, w);
      }
      else if (attrName.equalsIgnoreCase(ATTR_COMPRESS))
      {
        c = parseBoolean(p, values, c);
      }
      else if (attrName.equalsIgnoreCase(ATTR_ENCRYPT))
      {
        e = parseBoolean(p, values, e);
      }
      else if (attrName.equalsIgnoreCase(ATTR_ENCRYPTION_PASSPHRASE_FILE))
      {
        encPWFile = parseString(p, values, encPWFile);
      }
      else if (attrName.equalsIgnoreCase(
           ATTR_ENCRYPTION_SETTINGS_DEFINITION_ID))
      {
        encID = parseString(p, values, encID);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SIGN))
      {
        s = parseBoolean(p, values, s);
      }
      else if (attrName.equalsIgnoreCase(ATTR_MAX_MEGABYTES_PER_SECOND))
      {
        final Long maxMBLong = parseLong(p, values, null);
        if (maxMBLong == null)
        {
          maxMB = null;
        }
        else
        {
          maxMB = maxMBLong.intValue();
        }
      }
    }

    if (b == null)
    {
      throw new TaskException(ERR_EXPORT_TASK_NO_BACKEND_ID.get(
                                   getTaskEntryDN()));
    }

    if (l == null)
    {
      throw new TaskException(ERR_EXPORT_TASK_NO_LDIF_FILE.get(
                                   getTaskEntryDN()));
    }

    backendID = b;
    ldifFile = l;
    appendToLDIF = a;
    includeAttributes = Collections.unmodifiableList(Arrays.asList(iA));
    excludeAttributes = Collections.unmodifiableList(Arrays.asList(eA));
    includeBranches = Collections.unmodifiableList(Arrays.asList(iB));
    excludeBranches = Collections.unmodifiableList(Arrays.asList(eB));
    includeFilters = Collections.unmodifiableList(Arrays.asList(iF));
    excludeFilters = Collections.unmodifiableList(Arrays.asList(eF));
    wrapColumn = (int) w;
    compress = c;
    encrypt = e;
    encryptionPassphraseFile = encPWFile;
    encryptionSettingsDefinitionID = encID;
    sign = s;
    maxMegabytesPerSecond = maxMB;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_EXPORT.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_EXPORT.get();
  }



  /**
   * Retrieves the backend ID of the backend from which the data is to be
   * exported.
   *
   * @return  The backend ID of the backend from which the data is to be
   *          exported.
   */
  @NotNull()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Retrieves the path to the LDIF file to which the exported data should be
   * written.  It may be either an absolute path or one that is relative to the
   * server root.
   *
   * @return  The path to the LDIF file to which the exported data should be
   *          written.
   */
  @NotNull()
  public String getLDIFFile()
  {
    return ldifFile;
  }



  /**
   * Indicates whether to append to the LDIF file rather than overwriting it if
   * it already exists.
   *
   * @return  {@code true} if the server should append to an existing LDIF file,
   *          or {@code false} if the server should overwrite it.
   */
  public boolean appendToLDIF()
  {
    return appendToLDIF;
  }



  /**
   * Retrieves a list of base DNs of branches that should be included in the
   * export.
   *
   * @return  A list of base DNs of branches that should be included in the
   *          export, or an empty list if no entries should be excluded based on
   *          their location.
   */
  @NotNull()
  public List<String> getIncludeBranches()
  {
    return includeBranches;
  }



  /**
   * Retrieves a list of base DNs of branches that should be excluded from the
   * export.
   *
   * @return  A list of base DNs of branches that should be excluded from the
   *          export, or an empty list if no entries should be excluded based on
   *          their location.
   */
  @NotNull()
  public List<String> getExcludeBranches()
  {
    return excludeBranches;
  }



  /**
   * Retrieves a list of search filters that should be used to determine which
   * entries should be included in the export.
   *
   * @return  A list of search filters that should be used to determine which
   *          entries should be included in the export, or an empty list if no
   *          entries should be excluded based on their content.
   */
  @NotNull()
  public List<String> getIncludeFilters()
  {
    return includeFilters;
  }



  /**
   * Retrieves a list of search filters that should be used to determine which
   * entries should be excluded from the export.
   *
   * @return  A list of search filters that should be used to determine which
   *          entries should be excluded from the export, or an empty list if no
   *          entries should be excluded based on their content.
   */
  @NotNull()
  public List<String> getExcludeFilters()
  {
    return excludeFilters;
  }



  /**
   * Retrieves a list of the attributes that should be included in exported
   * entries.
   *
   * @return  A list of the attributes that should be included in exported
   *          entries, or an empty list if no attributes should be excluded.
   */
  @NotNull()
  public List<String> getIncludeAttributes()
  {
    return includeAttributes;
  }



  /**
   * Retrieves a list of the attributes that should be excluded from exported
   * entries.
   *
   * @return  A list of the attributes that should be excluded from exported
   *          entries, or an empty list if no attributes should be excluded.
   */
  @NotNull()
  public List<String> getExcludeAttributes()
  {
    return excludeAttributes;
  }



  /**
   * Retrieves the column number at which long lines should be wrapped.
   *
   * @return  The column number at which long lines should be wrapped, or a
   *          value less than or equal to zero to indicate that no wrapping
   *          should be performed.
   */
  public int getWrapColumn()
  {
    return wrapColumn;
  }



  /**
   * Indicates whether the LDIF data should be compressed as it is exported.
   *
   * @return  {@code true} if the LDIF data should be compressed as it is
   *          exported, or {@code false} if not.
   */
  public boolean compress()
  {
    return compress;
  }



  /**
   * Indicates whether the LDIF data should be encrypted as it is exported.
   *
   * @return  {@code true} if the LDIF data should be encrypted as it is
   *          exported, or {@code false} if not.
   */
  public boolean encrypt()
  {
    return encrypt;
  }



  /**
   * Retrieves the path to a file that contains the passphrase to use to
   * generate the encryption key.
   *
   * @return  The path to a file that contains the passphrase to use to
   *          generate the encryption key, or {@code null} if the LDIF file
   *          should not be encrypted or if the encryption key should be
   *          obtained through some other means.
   */
  @Nullable()
  public String getEncryptionPassphraseFile()
  {
    return encryptionPassphraseFile;
  }



  /**
   * Retrieves the identifier of the encryption settings definition to use to
   * generate the encryption key.
   *
   * @return  The identifier of the encryption settings definition to use to
   *          generate the encryption key, or {@code null} if the LDIF file
   *          should not be encrypted or if the encryption key should be
   *          obtained through some other means.
   */
  @Nullable()
  public String getEncryptionSettingsDefinitionID()
  {
    return encryptionSettingsDefinitionID;
  }



  /**
   * Indicates whether the exported LDIF data should include a signed hash.
   *
   * @return  {@code true} if the exported LDIF data should include a signed
   *          hash, or {@code false} if not.
   */
  public boolean sign()
  {
    return sign;
  }



  /**
   * Retrieves the maximum rate, in megabytes per second, at which the LDIF file
   * should be written.
   *
   * @return  The maximum rate, in megabytes per second, at which the LDIF file
   *          should be written, or {@code null} if the writing should not be
   *          rate limited.
   */
  @Nullable()
  public Integer getMaxMegabytesPerSecond()
  {
    return maxMegabytesPerSecond;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_EXPORT_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(20);

    attrs.add(new Attribute(ATTR_BACKEND_ID, backendID));
    attrs.add(new Attribute(ATTR_LDIF_FILE, ldifFile));
    attrs.add(new Attribute(ATTR_APPEND_TO_LDIF, String.valueOf(appendToLDIF)));
    attrs.add(new Attribute(ATTR_COMPRESS, String.valueOf(compress)));
    attrs.add(new Attribute(ATTR_ENCRYPT, String.valueOf(encrypt)));
    attrs.add(new Attribute(ATTR_SIGN, String.valueOf(sign)));

    if (! includeBranches.isEmpty())
    {
      attrs.add(new Attribute(ATTR_INCLUDE_BRANCH, includeBranches));
    }

    if (! excludeBranches.isEmpty())
    {
      attrs.add(new Attribute(ATTR_EXCLUDE_BRANCH, excludeBranches));
    }

    if (! includeAttributes.isEmpty())
    {
      attrs.add(new Attribute(ATTR_INCLUDE_ATTRIBUTE, includeAttributes));
    }

    if (! excludeAttributes.isEmpty())
    {
      attrs.add(new Attribute(ATTR_EXCLUDE_ATTRIBUTE, excludeAttributes));
    }

    if (! includeFilters.isEmpty())
    {
      attrs.add(new Attribute(ATTR_INCLUDE_FILTER, includeFilters));
    }

    if (! excludeFilters.isEmpty())
    {
      attrs.add(new Attribute(ATTR_EXCLUDE_FILTER, excludeFilters));
    }

    if (wrapColumn > 0)
    {
      attrs.add(new Attribute(ATTR_WRAP_COLUMN, String.valueOf(wrapColumn)));
    }

    if (encryptionPassphraseFile != null)
    {
      attrs.add(new Attribute(ATTR_ENCRYPTION_PASSPHRASE_FILE,
           encryptionPassphraseFile));
    }

    if (encryptionSettingsDefinitionID != null)
    {
      attrs.add(new Attribute(ATTR_ENCRYPTION_SETTINGS_DEFINITION_ID,
           encryptionSettingsDefinitionID));
    }

    if (maxMegabytesPerSecond != null)
    {
      attrs.add(new Attribute(ATTR_MAX_MEGABYTES_PER_SECOND,
           String.valueOf(maxMegabytesPerSecond)));
    }

    return attrs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    final List<TaskProperty> propList = Arrays.asList(
         PROPERTY_BACKEND_ID,
         PROPERTY_LDIF_FILE,
         PROPERTY_APPEND_TO_LDIF,
         PROPERTY_INCLUDE_BRANCH,
         PROPERTY_EXCLUDE_BRANCH,
         PROPERTY_INCLUDE_FILTER,
         PROPERTY_EXCLUDE_FILTER,
         PROPERTY_INCLUDE_ATTRIBUTE,
         PROPERTY_EXCLUDE_ATTRIBUTE,
         PROPERTY_WRAP_COLUMN,
         PROPERTY_COMPRESS,
         PROPERTY_ENCRYPT,
         PROPERTY_ENCRYPTION_PASSPHRASE_FILE,
         PROPERTY_ENCRYPTION_SETTINGS_DEFINITION_ID,
         PROPERTY_SIGN,
         PROPERTY_MAX_MEGABYTES_PER_SECOND);

    return Collections.unmodifiableList(propList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(30));

    props.put(PROPERTY_BACKEND_ID,
              Collections.<Object>singletonList(backendID));

    props.put(PROPERTY_LDIF_FILE,
              Collections.<Object>singletonList(ldifFile));

    props.put(PROPERTY_APPEND_TO_LDIF,
              Collections.<Object>singletonList(appendToLDIF));

    props.put(PROPERTY_INCLUDE_BRANCH,
              Collections.<Object>unmodifiableList(includeBranches));

    props.put(PROPERTY_EXCLUDE_BRANCH,
              Collections.<Object>unmodifiableList(excludeBranches));

    props.put(PROPERTY_INCLUDE_FILTER,
              Collections.<Object>unmodifiableList(includeFilters));

    props.put(PROPERTY_EXCLUDE_FILTER,
              Collections.<Object>unmodifiableList(excludeFilters));

    props.put(PROPERTY_INCLUDE_ATTRIBUTE,
              Collections.<Object>unmodifiableList(includeAttributes));

    props.put(PROPERTY_EXCLUDE_ATTRIBUTE,
              Collections.<Object>unmodifiableList(excludeAttributes));

    props.put(PROPERTY_WRAP_COLUMN,
              Collections.<Object>singletonList((long) wrapColumn));

    props.put(PROPERTY_COMPRESS,
              Collections.<Object>singletonList(compress));

    props.put(PROPERTY_ENCRYPT,
              Collections.<Object>singletonList(encrypt));

    if (encryptionPassphraseFile == null)
    {
      props.put(PROPERTY_ENCRYPTION_PASSPHRASE_FILE, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_ENCRYPTION_PASSPHRASE_FILE,
         Collections.<Object>singletonList(encryptionPassphraseFile));
    }

    if (encryptionSettingsDefinitionID == null)
    {
      props.put(PROPERTY_ENCRYPTION_SETTINGS_DEFINITION_ID,
           Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_ENCRYPTION_SETTINGS_DEFINITION_ID,
         Collections.<Object>singletonList(encryptionSettingsDefinitionID));
    }

    props.put(PROPERTY_SIGN, Collections.<Object>singletonList(sign));

    if (maxMegabytesPerSecond == null)
    {
      props.put(PROPERTY_MAX_MEGABYTES_PER_SECOND, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_MAX_MEGABYTES_PER_SECOND,
         Collections.<Object>singletonList(maxMegabytesPerSecond.longValue()));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
