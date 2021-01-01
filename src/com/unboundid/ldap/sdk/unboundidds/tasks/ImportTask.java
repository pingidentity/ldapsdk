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
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to import LDIF
 * content into a backend.
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
 *   <LI>The paths (on the server system) to the LDIF files containing the data
 *       to be imported.  At least one LDIF file path must be provided.</LI>
 *   <LI>The backend ID for the backend into which the data should be
 *       imported.  It may be omitted only if at least one include branch is
 *       provided.</LI>
 *   <LI>A flag that indicates whether to append to the existing data in the
 *       backend rather than destroying any existing data before beginning the
 *       import.</LI>
 *   <LI>A flag that indicates whether to replace entries that already exist
 *       when operating in append mode.</LI>
 *   <LI>An optional path (on the server system) to a file to which the server
 *       should write copies of any entries that are rejected, along with a
 *       message explaining why they were rejected.</LI>
 *   <LI>A flag that indicates whether to overwrite the reject file rather than
 *       append to it if it already exists.</LI>
 *   <LI>A flag that indicates whether to clear the entire contents of the
 *       backend even if it has multiple base DNs but only a subset of them
 *       were provided in the set of include branches.</LI>
 *   <LI>An optional list of base DNs for branches to include in the
 *       import.</LI>
 *   <LI>An optional list of base DNs for branches to exclude from the
 *       import.</LI>
 *   <LI>An optional list of search filters that may be used to determine
 *       whether an entry should be included in the import.</LI>
 *   <LI>An optional list of search filters that may be used to determine
 *       whether an entry should be excluded from the import.</LI>
 *   <LI>An optional list of attributes that should be included in the entries
 *       that are imported.</LI>
 *   <LI>An optional list of attributes that should be excluded from the entries
 *       that are imported.</LI>
 *   <LI>A flag that indicates whether the LDIF data to import is
 *       compressed.</LI>
 *   <LI>A flag that indicates whether the LDIF data to import is
 *       encrypted.</LI>
 *   <LI>A flag that indicates whether to skip schema validation for the data
 *       that is imported.</LI>
 *   <LI>The path to a file containing a passphrase to use to generate the
 *       encryption key.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ImportTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the import
   * task.
   */
  @NotNull static final String IMPORT_TASK_CLASS =
       "com.unboundid.directory.server.tasks.ImportTask";



  /**
   * The name of the attribute used to indicate whether to append to an existing
   * database rather than overwriting its content.
   */
  @NotNull private static final String ATTR_APPEND =
       "ds-task-import-append";



  /**
   * The name of the attribute used to specify the backend ID for the backend
   * into which to import the data.
   */
  @NotNull private static final String ATTR_BACKEND_ID =
       "ds-task-import-backend-id";



  /**
   * The name of the attribute used to indicate whether to clear the entire
   * backend when importing based on base DN.
   */
  @NotNull private static final String ATTR_CLEAR_BACKEND =
       "ds-task-import-clear-backend";



  /**
   * The name of the attribute used to specify the path to a file that contains
   * the passphrase to use to generate the encryption key.
   */
  @NotNull private static final String ATTR_ENCRYPTION_PASSPHRASE_FILE =
       "ds-task-import-encryption-passphrase-file";



  /**
   * The name of the attribute used to specify the attributes to exclude from
   * entries being imported.
   */
  @NotNull private static final String ATTR_EXCLUDE_ATTRIBUTE =
       "ds-task-import-exclude-attribute";



  /**
   * The name of the attribute used to specify the base DNs of branches to
   * exclude from the import.
   */
  @NotNull private static final String ATTR_EXCLUDE_BRANCH =
       "ds-task-import-exclude-branch";



  /**
   * The name of the attribute used to specify the filters used to determine
   * whether to exclude an entry from the import.
   */
  @NotNull private static final String ATTR_EXCLUDE_FILTER =
       "ds-task-import-exclude-filter";



  /**
   * The name of the attribute used to specify the attributes to include in
   * entries being imported.
   */
  @NotNull private static final String ATTR_INCLUDE_ATTRIBUTE =
       "ds-task-import-include-attribute";



  /**
   * The name of the attribute used to specify the base DNs of branches to
   * include in the import.
   */
  @NotNull private static final String ATTR_INCLUDE_BRANCH =
       "ds-task-import-include-branch";



  /**
   * The name of the attribute used to specify the filters used to determine
   * whether to include an entry in the import.
   */
  @NotNull private static final String ATTR_INCLUDE_FILTER =
       "ds-task-import-include-filter";



  /**
   * The name of the attribute used to indicate whether the LDIF data is
   * compressed.
   */
  @NotNull private static final String ATTR_IS_COMPRESSED =
       "ds-task-import-is-compressed";



  /**
   * The name of the attribute used to indicate whether the LDIF data is
   * encrypted.
   */
  @NotNull private static final String ATTR_IS_ENCRYPTED =
       "ds-task-import-is-encrypted";



  /**
   * The name of the attribute used to specify the paths to the LDIF files to be
   * imported.
   */
  @NotNull private static final String ATTR_LDIF_FILE =
       "ds-task-import-ldif-file";



  /**
   * The name of the attribute used to indicate whether to overwrite an existing
   * reject file.
   */
  @NotNull private static final String ATTR_OVERWRITE_REJECTS =
       "ds-task-import-overwrite-rejects";



  /**
   * The name of the attribute used to specify the path to the reject file.
   */
  @NotNull private static final String ATTR_REJECT_FILE =
       "ds-task-import-reject-file";



  /**
   * The name of the attribute used to indicate whether to replace existing
   * entries when appending to a database rather than overwriting it.
   */
  @NotNull private static final String ATTR_REPLACE_EXISTING =
       "ds-task-import-replace-existing";



  /**
   * The name of the attribute used to indicate whether to skip schema
   * validation for the import.
   */
  @NotNull private static final String ATTR_SKIP_SCHEMA_VALIDATION =
       "ds-task-import-skip-schema-validation";



  /**
   * The name of the attribute used to indicate whether to strip illegal
   * trailing spaces from LDIF records rather than rejecting those records.
   */
  @NotNull private static final String ATTR_STRIP_TRAILING_SPACES =
       "ds-task-import-strip-trailing-spaces";



  /**
   * The task property for the backend ID.
   */
  @NotNull private static final TaskProperty PROPERTY_BACKEND_ID =
       new TaskProperty(ATTR_BACKEND_ID, INFO_DISPLAY_NAME_BACKEND_ID.get(),
                        INFO_DESCRIPTION_BACKEND_ID_IMPORT.get(), String.class,
                        false, false, false);



  /**
   * The task property for the LDIF files.
   */
  @NotNull private static final TaskProperty PROPERTY_LDIF_FILE =
       new TaskProperty(ATTR_LDIF_FILE, INFO_DISPLAY_NAME_LDIF_FILE.get(),
                        INFO_DESCRIPTION_LDIF_FILE_IMPORT.get(), String.class,
                        true, true, false);



  /**
   * The task property for the append flag.
   */
  @NotNull private static final TaskProperty PROPERTY_APPEND =
       new TaskProperty(ATTR_APPEND, INFO_DISPLAY_NAME_APPEND_TO_DB.get(),
                        INFO_DESCRIPTION_APPEND_TO_DB.get(), Boolean.class,
                        false, false, true);



  /**
   * The task property for the replace existing flag.
   */
  @NotNull private static final TaskProperty PROPERTY_REPLACE_EXISTING =
       new TaskProperty(ATTR_REPLACE_EXISTING,
                        INFO_DISPLAY_NAME_REPLACE_EXISTING.get(),
                        INFO_DESCRIPTION_REPLACE_EXISTING.get(), Boolean.class,
                        false, false, true);



  /**
   * The task property for the reject file.
   */
  @NotNull private static final TaskProperty PROPERTY_REJECT_FILE =
       new TaskProperty(ATTR_REJECT_FILE,
                        INFO_DISPLAY_NAME_REJECT_FILE.get(),
                        INFO_DESCRIPTION_REJECT_FILE.get(), String.class,
                        false, false, false);



  /**
   * The task property for the overwrite rejects flag.
   */
  @NotNull private static final TaskProperty PROPERTY_OVERWRITE_REJECTS =
       new TaskProperty(ATTR_OVERWRITE_REJECTS,
                        INFO_DISPLAY_NAME_OVERWRITE_REJECTS.get(),
                        INFO_DESCRIPTION_OVERWRITE_REJECTS.get(), Boolean.class,
                        false, false, true);



  /**
   * The task property for the clear backend flag.
   */
  @NotNull private static final TaskProperty PROPERTY_CLEAR_BACKEND =
       new TaskProperty(ATTR_CLEAR_BACKEND,
                        INFO_DISPLAY_NAME_CLEAR_BACKEND.get(),
                        INFO_DESCRIPTION_CLEAR_BACKEND.get(), Boolean.class,
                        false, false, true);



  /**
   * The task property for the include branches.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_BRANCH =
       new TaskProperty(ATTR_INCLUDE_BRANCH,
                        INFO_DISPLAY_NAME_INCLUDE_BRANCH.get(),
                        INFO_DESCRIPTION_INCLUDE_BRANCH_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude branches.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_BRANCH =
       new TaskProperty(ATTR_EXCLUDE_BRANCH,
                        INFO_DISPLAY_NAME_EXCLUDE_BRANCH.get(),
                        INFO_DESCRIPTION_EXCLUDE_BRANCH_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the include filters.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_FILTER =
       new TaskProperty(ATTR_INCLUDE_FILTER,
                        INFO_DISPLAY_NAME_INCLUDE_FILTER.get(),
                        INFO_DESCRIPTION_INCLUDE_FILTER_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude filters.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_FILTER =
       new TaskProperty(ATTR_EXCLUDE_FILTER,
                        INFO_DISPLAY_NAME_EXCLUDE_FILTER.get(),
                        INFO_DESCRIPTION_EXCLUDE_FILTER_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the include attributes.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_ATTRIBUTE =
       new TaskProperty(ATTR_INCLUDE_ATTRIBUTE,
                        INFO_DISPLAY_NAME_INCLUDE_ATTRIBUTE.get(),
                        INFO_DESCRIPTION_INCLUDE_ATTRIBUTE_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the exclude attributes.
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_ATTRIBUTE =
       new TaskProperty(ATTR_EXCLUDE_ATTRIBUTE,
                        INFO_DISPLAY_NAME_EXCLUDE_ATTRIBUTE.get(),
                        INFO_DESCRIPTION_EXCLUDE_ATTRIBUTE_IMPORT.get(),
                        String.class, false, true, true);



  /**
   * The task property for the is compressed flag.
   */
  @NotNull private static final TaskProperty PROPERTY_IS_COMPRESSED =
       new TaskProperty(ATTR_IS_COMPRESSED,
                        INFO_DISPLAY_NAME_IS_COMPRESSED_IMPORT.get(),
                        INFO_DESCRIPTION_IS_COMPRESSED_IMPORT.get(),
                        Boolean.class, false, false, false);



  /**
   * The task property for the is encrypted flag.
   */
  @NotNull private static final TaskProperty PROPERTY_IS_ENCRYPTED =
       new TaskProperty(ATTR_IS_ENCRYPTED,
                        INFO_DISPLAY_NAME_IS_ENCRYPTED_IMPORT.get(),
                        INFO_DESCRIPTION_IS_ENCRYPTED_IMPORT.get(),
                        Boolean.class, false, false, false);



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
   * The task property for the skip schema validation flag.
   */
  @NotNull private static final TaskProperty PROPERTY_SKIP_SCHEMA_VALIDATION =
       new TaskProperty(ATTR_SKIP_SCHEMA_VALIDATION,
                        INFO_DISPLAY_NAME_SKIP_SCHEMA_VALIDATION.get(),
                        INFO_DESCRIPTION_SKIP_SCHEMA_VALIDATION.get(),
                        Boolean.class, false, false, false);



  /**
   * The task property for the strip trailing spaces flag.
   */
  @NotNull private static final TaskProperty PROPERTY_STRIP_TRAILING_SPACES =
       new TaskProperty(ATTR_STRIP_TRAILING_SPACES,
                        INFO_DISPLAY_NAME_STRIP_TRAILING_SPACES.get(),
                        INFO_DESCRIPTION_STRIP_TRAILING_SPACES.get(),
                        Boolean.class, false, false, false);



  /**
   * The name of the object class used in import task entries.
   */
  @NotNull private static final String OC_IMPORT_TASK = "ds-task-import";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9114913680318281750L;



  // Indicates whether to append to the database rather than overwriting it.
  private final boolean append;

  // Indicates whether to clear the entire backend when importing by base DN.
  private final boolean clearBackend;

  // Indicates whether the LDIF data is compressed.
  private final boolean isCompressed;

  // Indicates whether the LDIF data is encrypted.
  private final boolean isEncrypted;

  // Indicates whether to overwrite an existing reject file.
  private final boolean overwriteRejects;

  // Indicates whether to replace existing entries when appending to the DB.
  private final boolean replaceExisting;

  // Indicates whether to skip schema validation for the import.
  private final boolean skipSchemaValidation;

  // Indicates whether to strip illegal trailing spaces from LDIF records rather
  // than rejecting them.
  private final boolean stripTrailingSpaces;

  // The set of exclude attributes for the import.
  @NotNull private final List<String> excludeAttributes;

  // The set of exclude branches for the import.
  @NotNull private final List<String> excludeBranches;

  // The set of exclude filters for the import.
  @NotNull private final List<String> excludeFilters;

  // The set of include attributes for the import.
  @NotNull private final List<String> includeAttributes;

  // The set of include branches for the import.
  @NotNull private final List<String> includeBranches;

  // The set of include filters for the import.
  @NotNull private final List<String> includeFilters;

  // The paths to the LDIF files to be imported.
  @NotNull private final List<String> ldifFiles;

  // The backend ID of the backend to import.
  @Nullable private final String backendID;

  // The path to a file containing the passphrase to use to generate the
  // encryption key.
  @Nullable private final String encryptionPassphraseFile;

  // The path to the reject file to write.
  @Nullable private final String rejectFile;



  /**
   * Creates a new uninitialized import task instance which should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public ImportTask()
  {
    append = false;
    clearBackend = false;
    isCompressed = false;
    isEncrypted = false;
    overwriteRejects = false;
    replaceExisting = false;
    skipSchemaValidation = false;
    stripTrailingSpaces = false;
    encryptionPassphraseFile = null;
    excludeAttributes = null;
    excludeBranches = null;
    excludeFilters = null;
    includeAttributes = null;
    includeBranches = null;
    includeFilters = null;
    ldifFiles = null;
    backendID = null;
    rejectFile = null;
  }



  /**
   * Creates a new import task with the provided backend.  It will overwrite
   * the contents of the backend with the data in the provided LDIF file.
   *
   * @param  taskID     The task ID to use for this task.  If it is {@code null}
   *                    then a UUID will be generated for use as the task ID.
   * @param  backendID  The backend ID of the backend into which the data should
   *                    be imported.  It must not be {@code null}.
   * @param  ldifFile   The path to the LDIF file containing the data to be
   *                    imported.  It may be an absolute path or a path relative
   *                    to the server install root.  It must not be
   *                    {@code null}.
   */
  public ImportTask(@Nullable final String taskID,
                    @NotNull final String backendID,
                    @NotNull final String ldifFile)
  {
    this(taskID, Collections.singletonList(ldifFile), backendID, false, false,
         null, false, true, null, null, null, null, null, null, false, false,
         false, null, null, null, null, null);

    Validator.ensureNotNull(ldifFile);
  }



  /**
   * Creates a new import task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  ldifFiles               The paths to the LDIF file containing the
   *                                 data to be imported.  The paths may be
   *                                 either absolute or relative to the server
   *                                 install root.  It must not be {@code null}
   *                                 or empty.
   * @param  backendID               The backend ID of the backend into which
   *                                 the data should be imported.  It may be
   *                                 {@code null} only if one or more include
   *                                 branches was specified.
   * @param  append                  Indicates whether to append to the existing
   *                                 data rather than overwriting it.
   * @param  replaceExisting         Indicates whether to replace existing
   *                                 entries when appending to the database.
   * @param  rejectFile              The path to a file into which information
   *                                 will be written about rejected entries.  It
   *                                 may be {@code null} if no reject file is to
   *                                 be maintained.
   * @param  overwriteRejects        Indicates whether to overwrite an existing
   *                                 rejects file rather than appending to it.
   * @param  clearBackend            Indicates whether to clear data below all
   *                                 base DNs in the backend.  It must be
   *                                 {@code true} if the backend was specified
   *                                 using a backend ID and no include branches
   *                                 are specified and {@code append} is
   *                                 {@code false}.  If include branches were
   *                                 specified, or if data is being appended to
   *                                 the backend, then it may be either
   *                                 {@code true} or {@code false}.
   * @param  includeBranches         The set of base DNs below which to import
   *                                 the data.  It may be {@code null} or empty
   *                                 if a backend ID was specified and data
   *                                 should be imported below all base DNs
   *                                 defined in the backend.  Otherwise, at
   *                                 least one include branch must be provided,
   *                                 and any data not under one of the include
   *                                 branches will be excluded from the import.
   *                                 All include branches must be within the
   *                                 scope of the same backend.
   * @param  excludeBranches         The set of base DNs to exclude from the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 location.
   * @param  includeFilters          The set of filters to use to determine
   *                                 which entries should be included in the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 content.
   * @param  excludeFilters          The set of filters to use to determine
   *                                 which entries should be excluded from the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 content.
   * @param  includeAttributes       The set of attributes to include in the
   *                                 entries being imported.  It may be
   *                                 {@code null} or empty if no attributes
   *                                 should be excluded from the import.
   * @param  excludeAttributes       The set of attributes to exclude from the
   *                                 entries being imported.  It may be
   *                                 {@code null} or empty if no attributes
   *                                 should be excluded from the import.
   * @param  isCompressed            Indicates whether the data in the LDIF
   *                                 file(s) is compressed.
   * @param  isEncrypted             Indicates whether the data in the LDIF
   *                                 file(s) is encrypted.
   * @param  skipSchemaValidation    Indicates whether to skip schema validation
   *                                 during the import.
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
  public ImportTask(@Nullable final String taskID,
              @NotNull final List<String> ldifFiles,
              @Nullable final String backendID,
              final boolean append,
              final boolean replaceExisting,
              @Nullable final String rejectFile,
              final boolean overwriteRejects, final boolean clearBackend,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final boolean isCompressed, final boolean isEncrypted,
              final boolean skipSchemaValidation,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, ldifFiles, backendID, append, replaceExisting, rejectFile,
         overwriteRejects, clearBackend, includeBranches, excludeBranches,
         includeFilters, excludeFilters, includeAttributes, excludeAttributes,
         isCompressed, isEncrypted, skipSchemaValidation, false,
         scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnCompletion, notifyOnError);
  }



  /**
   * Creates a new import task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  ldifFiles               The paths to the LDIF file containing the
   *                                 data to be imported.  The paths may be
   *                                 either absolute or relative to the server
   *                                 install root.  It must not be {@code null}
   *                                 or empty.
   * @param  backendID               The backend ID of the backend into which
   *                                 the data should be imported.  It may be
   *                                 {@code null} only if one or more include
   *                                 branches was specified.
   * @param  append                  Indicates whether to append to the existing
   *                                 data rather than overwriting it.
   * @param  replaceExisting         Indicates whether to replace existing
   *                                 entries when appending to the database.
   * @param  rejectFile              The path to a file into which information
   *                                 will be written about rejected entries.  It
   *                                 may be {@code null} if no reject file is to
   *                                 be maintained.
   * @param  overwriteRejects        Indicates whether to overwrite an existing
   *                                 rejects file rather than appending to it.
   * @param  clearBackend            Indicates whether to clear data below all
   *                                 base DNs in the backend.  It must be
   *                                 {@code true} if the backend was specified
   *                                 using a backend ID and no include branches
   *                                 are specified and {@code append} is
   *                                 {@code false}.  If include branches were
   *                                 specified, or if data is being appended to
   *                                 the backend, then it may be either
   *                                 {@code true} or {@code false}.
   * @param  includeBranches         The set of base DNs below which to import
   *                                 the data.  It may be {@code null} or empty
   *                                 if a backend ID was specified and data
   *                                 should be imported below all base DNs
   *                                 defined in the backend.  Otherwise, at
   *                                 least one include branch must be provided,
   *                                 and any data not under one of the include
   *                                 branches will be excluded from the import.
   *                                 All include branches must be within the
   *                                 scope of the same backend.
   * @param  excludeBranches         The set of base DNs to exclude from the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 location.
   * @param  includeFilters          The set of filters to use to determine
   *                                 which entries should be included in the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 content.
   * @param  excludeFilters          The set of filters to use to determine
   *                                 which entries should be excluded from the
   *                                 import.  It may be {@code null} or empty if
   *                                 no data is to be excluded based on its
   *                                 content.
   * @param  includeAttributes       The set of attributes to include in the
   *                                 entries being imported.  It may be
   *                                 {@code null} or empty if no attributes
   *                                 should be excluded from the import.
   * @param  excludeAttributes       The set of attributes to exclude from the
   *                                 entries being imported.  It may be
   *                                 {@code null} or empty if no attributes
   *                                 should be excluded from the import.
   * @param  isCompressed            Indicates whether the data in the LDIF
   *                                 file(s) is compressed.
   * @param  isEncrypted             Indicates whether the data in the LDIF
   *                                 file(s) is encrypted.
   * @param  skipSchemaValidation    Indicates whether to skip schema validation
   *                                 during the import.
   * @param  stripTrailingSpaces     Indicates whether to strip illegal trailing
   *                                 spaces found in LDIF records rather than
   *                                 rejecting those records.
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
  public ImportTask(@Nullable final String taskID,
              @NotNull final List<String> ldifFiles,
              @Nullable final String backendID,
              final boolean append,
              final boolean replaceExisting,
              @Nullable final String rejectFile,
              final boolean overwriteRejects, final boolean clearBackend,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final boolean isCompressed, final boolean isEncrypted,
              final boolean skipSchemaValidation,
              final boolean stripTrailingSpaces,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, ldifFiles, backendID, append, replaceExisting, rejectFile,
         overwriteRejects, clearBackend, includeBranches, excludeBranches,
         includeFilters, excludeFilters, includeAttributes, excludeAttributes,
         isCompressed, isEncrypted, null, skipSchemaValidation,
         stripTrailingSpaces, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnCompletion, notifyOnError);
  }



  /**
   * Creates a new import task with the provided information.
   *
   * @param  taskID                    The task ID to use for this task.  If it
   *                                   is {@code null} then a UUID will be
   *                                   generated for use as the task ID.
   * @param  ldifFiles                 The paths to the LDIF file containing the
   *                                   data to be imported.  The paths may be
   *                                   either absolute or relative to the server
   *                                   install root.  It must not be
   *                                   {@code null} or empty.
   * @param  backendID                 The backend ID of the backend into which
   *                                   the data should be imported.  It may be
   *                                   {@code null} only if one or more include
   *                                   branches was specified.
   * @param  append                    Indicates whether to append to the
   *                                   existing data rather than overwriting it.
   * @param  replaceExisting           Indicates whether to replace existing
   *                                   entries when appending to the database.
   * @param  rejectFile                The path to a file into which
   *                                   information will be written about
   *                                   rejected entries.  It may be {@code null}
   *                                   if no reject file is to be maintained.
   * @param  overwriteRejects          Indicates whether to overwrite an
   *                                   existing rejects file rather than
   *                                   appending to it.
   * @param  clearBackend              Indicates whether to clear data below all
   *                                   base DNs in the backend.  It must be
   *                                   {@code true} if the backend was specified
   *                                   using a backend ID and no include
   *                                   branches are specified and {@code append}
   *                                   is {@code false}.  If include branches
   *                                   were specified, or if data is being
   *                                   appended to the backend, then it may be
   *                                   either {@code true} or {@code false}.
   * @param  includeBranches           The set of base DNs below which to import
   *                                   the data.  It may be {@code null} or
   *                                   empty if a backend ID was specified and
   *                                   data should be imported below all base
   *                                   DNs defined in the backend.  Otherwise,
   *                                   at least one include branch must be
   *                                   provided, and any data not under one of
   *                                   the include branches will be excluded
   *                                   from the import.  All include branches
   *                                   must be within the scope of the same
   *                                   backend.
   * @param  excludeBranches           The set of base DNs to exclude from the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   location.
   * @param  includeFilters            The set of filters to use to determine
   *                                   which entries should be included in the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   content.
   * @param  excludeFilters            The set of filters to use to determine
   *                                   which entries should be excluded from the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   content.
   * @param  includeAttributes         The set of attributes to include in the
   *                                   entries being imported.  It may be
   *                                   {@code null} or empty if no attributes
   *                                   should be excluded from the import.
   * @param  excludeAttributes         The set of attributes to exclude from the
   *                                   entries being imported.  It may be
   *                                   {@code null} or empty if no attributes
   *                                   should be excluded from the import.
   * @param  isCompressed              Indicates whether the data in the LDIF
   *                                   file(s) is compressed.
   * @param  isEncrypted               Indicates whether the data in the LDIF
   *                                   file(s) is encrypted.
   * @param  encryptionPassphraseFile  The path to a file containing the
   *                                   passphrase to use to generate the
   *                                   encryption key.  It amy be {@code null}
   *                                   if the backup is not to be encrypted, or
   *                                   if the key should be obtained in some
   *                                   other way.
   * @param  skipSchemaValidation      Indicates whether to skip schema
   *                                   validation during the import.
   * @param  stripTrailingSpaces       Indicates whether to strip illegal
   *                                   trailing spaces found in LDIF records
   *                                   rather than rejecting those records.
   * @param  scheduledStartTime        The time that this task should start
   *                                   running.
   * @param  dependencyIDs             The list of task IDs that will be
   *                                   required to complete before this task
   *                                   will be eligible to start.
   * @param  failedDependencyAction    Indicates what action should be taken if
   *                                   any of the dependencies for this task do
   *                                   not complete successfully.
   * @param  notifyOnCompletion        The list of e-mail addresses of
   *                                   individuals that should be notified when
   *                                   this task completes.
   * @param  notifyOnError             The list of e-mail addresses of
   *                                   individuals that should be notified if
   *                                   this task does not complete successfully.
   */
  public ImportTask(@Nullable final String taskID,
              @NotNull final List<String> ldifFiles,
              @Nullable final String backendID,
              final boolean append,
              final boolean replaceExisting,
              @Nullable final String rejectFile,
              final boolean overwriteRejects, final boolean clearBackend,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final boolean isCompressed, final boolean isEncrypted,
              @Nullable final String encryptionPassphraseFile,
              final boolean skipSchemaValidation,
              final boolean stripTrailingSpaces,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, ldifFiles, backendID, append, replaceExisting, rejectFile,
         overwriteRejects, clearBackend, includeBranches, excludeBranches,
         includeFilters, excludeFilters, includeAttributes,
         excludeAttributes, isCompressed, isEncrypted,
         encryptionPassphraseFile, skipSchemaValidation, stripTrailingSpaces,
         scheduledStartTime, dependencyIDs, failedDependencyAction, null,
         notifyOnCompletion, null, notifyOnError, null, null, null);
  }



  /**
   * Creates a new import task with the provided information.
   *
   * @param  taskID                    The task ID to use for this task.  If it
   *                                   is {@code null} then a UUID will be
   *                                   generated for use as the task ID.
   * @param  ldifFiles                 The paths to the LDIF file containing the
   *                                   data to be imported.  The paths may be
   *                                   either absolute or relative to the server
   *                                   install root.  It must not be
   *                                   {@code null} or empty.
   * @param  backendID                 The backend ID of the backend into which
   *                                   the data should be imported.  It may be
   *                                   {@code null} only if one or more include
   *                                   branches was specified.
   * @param  append                    Indicates whether to append to the
   *                                   existing data rather than overwriting it.
   * @param  replaceExisting           Indicates whether to replace existing
   *                                   entries when appending to the database.
   * @param  rejectFile                The path to a file into which
   *                                   information will be written about
   *                                   rejected entries.  It may be {@code null}
   *                                   if no reject file is to be maintained.
   * @param  overwriteRejects          Indicates whether to overwrite an
   *                                   existing rejects file rather than
   *                                   appending to it.
   * @param  clearBackend              Indicates whether to clear data below all
   *                                   base DNs in the backend.  It must be
   *                                   {@code true} if the backend was specified
   *                                   using a backend ID and no include
   *                                   branches are specified and {@code append}
   *                                   is {@code false}.  If include branches
   *                                   were specified, or if data is being
   *                                   appended to the backend, then it may be
   *                                   either {@code true} or {@code false}.
   * @param  includeBranches           The set of base DNs below which to import
   *                                   the data.  It may be {@code null} or
   *                                   empty if a backend ID was specified and
   *                                   data should be imported below all base
   *                                   DNs defined in the backend.  Otherwise,
   *                                   at least one include branch must be
   *                                   provided, and any data not under one of
   *                                   the include branches will be excluded
   *                                   from the import.  All include branches
   *                                   must be within the scope of the same
   *                                   backend.
   * @param  excludeBranches           The set of base DNs to exclude from the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   location.
   * @param  includeFilters            The set of filters to use to determine
   *                                   which entries should be included in the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   content.
   * @param  excludeFilters            The set of filters to use to determine
   *                                   which entries should be excluded from the
   *                                   import.  It may be {@code null} or empty
   *                                   if no data is to be excluded based on its
   *                                   content.
   * @param  includeAttributes         The set of attributes to include in the
   *                                   entries being imported.  It may be
   *                                   {@code null} or empty if no attributes
   *                                   should be excluded from the import.
   * @param  excludeAttributes         The set of attributes to exclude from the
   *                                   entries being imported.  It may be
   *                                   {@code null} or empty if no attributes
   *                                   should be excluded from the import.
   * @param  isCompressed              Indicates whether the data in the LDIF
   *                                   file(s) is compressed.
   * @param  isEncrypted               Indicates whether the data in the LDIF
   *                                   file(s) is encrypted.
   * @param  encryptionPassphraseFile  The path to a file containing the
   *                                   passphrase to use to generate the
   *                                   encryption key.  It amy be {@code null}
   *                                   if the backup is not to be encrypted, or
   *                                   if the key should be obtained in some
   *                                   other way.
   * @param  skipSchemaValidation      Indicates whether to skip schema
   *                                   validation during the import.
   * @param  stripTrailingSpaces       Indicates whether to strip illegal
   *                                   trailing spaces found in LDIF records
   *                                   rather than rejecting those records.
   * @param  scheduledStartTime        The time that this task should start
   *                                   running.
   * @param  dependencyIDs             The list of task IDs that will be
   *                                   required to complete before this task
   *                                   will be eligible to start.
   * @param  failedDependencyAction    Indicates what action should be taken if
   *                                   any of the dependencies for this task do
   *                                   not complete successfully.
   * @param  notifyOnStart             The list of e-mail addresses of
   *                                   individuals that should be notified when
   *                                   this task starts running.
   * @param  notifyOnCompletion        The list of e-mail addresses of
   *                                   individuals that should be notified when
   *                                   this task completes.
   * @param  notifyOnSuccess           The list of e-mail addresses of
   *                                   individuals that should be notified if
   *                                   this task completes successfully.
   * @param  notifyOnError             The list of e-mail addresses of
   *                                   individuals that should be notified if
   *                                   this task does not complete successfully.
   * @param  alertOnStart              Indicates whether the server should send
   *                                   an alert notification when this task
   *                                   starts.
   * @param  alertOnSuccess            Indicates whether the server should send
   *                                   an alert notification if this task
   *                                   completes successfully.
   * @param  alertOnError              Indicates whether the server should send
   *                                   an alert notification if this task fails
   *                                   to complete successfully.
   */
  public ImportTask(@Nullable final String taskID,
              @NotNull final List<String> ldifFiles,
              @Nullable final String backendID, final boolean append,
              final boolean replaceExisting,
              @Nullable final String rejectFile,
              final boolean overwriteRejects, final boolean clearBackend,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final List<String> includeAttributes,
              @Nullable final List<String> excludeAttributes,
              final boolean isCompressed, final boolean isEncrypted,
              @Nullable final String encryptionPassphraseFile,
              final boolean skipSchemaValidation,
              final boolean stripTrailingSpaces,
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
    super(taskID, IMPORT_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    Validator.ensureNotNull(ldifFiles);
    Validator.ensureFalse(ldifFiles.isEmpty(),
         "ImportTask.ldifFiles must not be empty.");
    Validator.ensureFalse((backendID == null) &&
         ((includeBranches == null) || includeBranches.isEmpty()));
    Validator.ensureTrue(clearBackend || append ||
         ((includeBranches != null) && (! includeBranches.isEmpty())));

    this.ldifFiles = Collections.unmodifiableList(ldifFiles);
    this.backendID = backendID;
    this.append = append;
    this.replaceExisting = replaceExisting;
    this.rejectFile = rejectFile;
    this.overwriteRejects = overwriteRejects;
    this.clearBackend = clearBackend;
    this.isCompressed = isCompressed;
    this.isEncrypted = isEncrypted;
    this.encryptionPassphraseFile = encryptionPassphraseFile;
    this.skipSchemaValidation = skipSchemaValidation;
    this.stripTrailingSpaces = stripTrailingSpaces;

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
   * Creates a new import task from the provided entry.
   *
   * @param  entry  The entry to use to create this import task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as an import
   *                         task entry.
   */
  public ImportTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the set of LDIF files.  It must be present.
    final String[] files = entry.getAttributeValues(ATTR_LDIF_FILE);
    if ((files == null) || (files.length == 0))
    {
      throw new TaskException(ERR_IMPORT_TASK_NO_LDIF.get(getTaskEntryDN()));
    }
    else
    {
      ldifFiles = Collections.unmodifiableList(Arrays.asList(files));
    }


    // Get the backend ID.  It may be absent.
    backendID = entry.getAttributeValue(ATTR_BACKEND_ID);


    // Get the append flag.  It may be absent.
    append = parseBooleanValue(entry, ATTR_APPEND, false);


    // Get the replaceExisting flag.  It may be absent.
    replaceExisting = parseBooleanValue(entry, ATTR_REPLACE_EXISTING, false);


    // Get the reject file.  It may be absent.
    rejectFile = entry.getAttributeValue(ATTR_REJECT_FILE);


    // Get the overwriteRejects flag.  It may be absent.
    overwriteRejects = parseBooleanValue(entry, ATTR_OVERWRITE_REJECTS, false);


    // Get the clearBackend flag.  It may be absent.
    clearBackend = parseBooleanValue(entry, ATTR_CLEAR_BACKEND, false);


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


    // Get the isCompressed flag.  It may be absent.
    isCompressed = parseBooleanValue(entry, ATTR_IS_COMPRESSED, false);


    // Get the isEncrypted flag.  It may be absent.
    isEncrypted = parseBooleanValue(entry, ATTR_IS_ENCRYPTED, false);


    // Get the path to the encryption passphrase file.  It may be absent.
    encryptionPassphraseFile =
         entry.getAttributeValue(ATTR_ENCRYPTION_PASSPHRASE_FILE);


    // Get the skipSchemaValidation flag.  It may be absent.
    skipSchemaValidation = parseBooleanValue(entry, ATTR_SKIP_SCHEMA_VALIDATION,
                                             false);


    // Get the stripTrailingSpaces flag.  It may be absent.
    stripTrailingSpaces = parseBooleanValue(entry, ATTR_STRIP_TRAILING_SPACES,
                                            false);
  }



  /**
   * Creates a new import task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid import task.
   */
  public ImportTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(IMPORT_TASK_CLASS, properties);

    boolean  a  = false;
    boolean  c  = false;
    boolean  cB = true;
    boolean  e  = false;
    boolean  o  = false;
    boolean  r  = false;
    boolean  ss = false;
    boolean  st = false;
    String   b  = null;
    String   pF = null;
    String   rF = null;
    String[] eA = StaticUtils.NO_STRINGS;
    String[] eB = StaticUtils.NO_STRINGS;
    String[] eF = StaticUtils.NO_STRINGS;
    String[] iA = StaticUtils.NO_STRINGS;
    String[] iB = StaticUtils.NO_STRINGS;
    String[] iF = StaticUtils.NO_STRINGS;
    String[] l  = StaticUtils.NO_STRINGS;

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
        l = parseStrings(p, values, l);
      }
      else if (attrName.equalsIgnoreCase(ATTR_APPEND))
      {
        a = parseBoolean(p, values, a);
      }
      else if (attrName.equalsIgnoreCase(ATTR_REPLACE_EXISTING))
      {
        r = parseBoolean(p, values, r);
      }
      else if (attrName.equalsIgnoreCase(ATTR_REJECT_FILE))
      {
        rF = parseString(p, values, rF);
      }
      else if (attrName.equalsIgnoreCase(ATTR_OVERWRITE_REJECTS))
      {
        o = parseBoolean(p, values, o);
      }
      else if (attrName.equalsIgnoreCase(ATTR_CLEAR_BACKEND))
      {
        cB = parseBoolean(p, values, cB);
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
      else if (attrName.equalsIgnoreCase(ATTR_IS_COMPRESSED))
      {
        c = parseBoolean(p, values, c);
      }
      else if (attrName.equalsIgnoreCase(ATTR_IS_ENCRYPTED))
      {
        e = parseBoolean(p, values, e);
      }
      else if (attrName.equalsIgnoreCase(ATTR_ENCRYPTION_PASSPHRASE_FILE))
      {
        pF = parseString(p, values, pF);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SKIP_SCHEMA_VALIDATION))
      {
        ss = parseBoolean(p, values, ss);
      }
      else if (attrName.equalsIgnoreCase(ATTR_STRIP_TRAILING_SPACES))
      {
        st = parseBoolean(p, values, st);
      }
    }

    if ((b == null) && (iB.length == 0))
    {
      throw new TaskException(
                     ERR_IMPORT_TASK_NO_BACKEND_ID_OR_INCLUDE_BRANCHES.get(
                          getTaskEntryDN()));
    }

    if (l == null)
    {
      throw new TaskException(ERR_IMPORT_TASK_NO_LDIF.get(
                                   getTaskEntryDN()));
    }

    backendID = b;
    ldifFiles = Collections.unmodifiableList(Arrays.asList(l));
    append = a;
    replaceExisting = r;
    rejectFile = rF;
    overwriteRejects = o;
    clearBackend = cB;
    includeAttributes = Collections.unmodifiableList(Arrays.asList(iA));
    excludeAttributes = Collections.unmodifiableList(Arrays.asList(eA));
    includeBranches = Collections.unmodifiableList(Arrays.asList(iB));
    excludeBranches = Collections.unmodifiableList(Arrays.asList(eB));
    includeFilters = Collections.unmodifiableList(Arrays.asList(iF));
    excludeFilters = Collections.unmodifiableList(Arrays.asList(eF));
    isCompressed = c;
    isEncrypted = e;
    encryptionPassphraseFile = pF;
    skipSchemaValidation = ss;
    stripTrailingSpaces = st;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_IMPORT.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_IMPORT.get();
  }



  /**
   * Retrieves the paths to the LDIF files containing the data to be imported.
   * The paths may be absolute or relative to the server root.
   *
   * @return  The paths to the LDIF files containing the data to be imported.
   */
  @NotNull()
  public List<String> getLDIFFiles()
  {
    return ldifFiles;
  }



  /**
   * Retrieves the backend ID of the backend into which the data should be
   * imported.
   *
   * @return  The backend ID of the backend into which the data should be
   *          imported, or {@code null} if no backend ID was specified and the
   *          backend will be identified from the include branches.
   */
  @Nullable()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Indicates whether the import should append to the data in the backend
   * rather than clearing the backend before performing the import.
   *
   * @return  {@code true} if the contents of the existing backend should be
   *          retained and the new data appended to it, or {@code false} if the
   *          existing content should be cleared prior to performing the import.
   */
  public boolean append()
  {
    return append;
  }



  /**
   * Indicates whether to replace existing entries when appending data to the
   * backend.  This is only applicable if {@code append()} returns {@code true}.
   *
   * @return  {@code true} if entries already present in the backend should be
   *          replaced if that entry is also present in the LDIF file, or
   *          {@code false} if entries already present in the backend should be
   *          retained and the corresponding entry contained in the LDIF should
   *          be skipped.
   */
  public boolean replaceExistingEntries()
  {
    return replaceExisting;
  }



  /**
   * Retrieves the path to a file to which rejected entries should be written.
   *
   * @return  The path to a file to which rejected entries should be written, or
   *          {@code null} if a rejected entries file should not be maintained.
   */
  @Nullable()
  public String getRejectFile()
  {
    return rejectFile;
  }



  /**
   * Indicates whether an existing reject file should be overwritten rather than
   * appending to it.
   *
   * @return  {@code true} if an existing reject file should be overwritten, or
   *          {@code false} if the server should append to it.
   */
  public boolean overwriteRejectFile()
  {
    return overwriteRejects;
  }



  /**
   * Indicates whether data below all base DNs defined in the backend should be
   * cleared before performing the import.  This is not applicable if the import
   * is to append to the backend, or if the backend only has a single base DN.
   *
   * @return  {@code true} if data below all base DNs in the backend should be
   *          cleared, or {@code false} if only data below the base DNs that
   *          correspond to the configured include branches should be cleared.
   */
  public boolean clearBackend()
  {
    return clearBackend;
  }



  /**
   * Retrieves the list of base DNs for branches that should be included in the
   * import.
   *
   * @return  The set of base DNs for branches that should be included in the
   *          import, or an empty list if data should be imported from all base
   *          DNs in the associated backend.
   */
  @NotNull()
  public List<String> getIncludeBranches()
  {
    return includeBranches;
  }



  /**
   * Retrieves the list of base DNs of branches that should be excluded from the
   * import.
   *
   * @return  The list of base DNs of branches that should be excluded from the
   *          import, or an empty list if no entries should be excluded from the
   *          import based on their location.
   */
  @NotNull()
  public List<String> getExcludeBranches()
  {
    return excludeBranches;
  }



  /**
   * Retrieves the list of search filters that may be used to identify which
   * entries should be included in the import.
   *
   * @return  The list of search filters that may be used to identify which
   *          entries should be included in the import, or an empty list if no
   *          entries should be excluded from the import based on their content.
   */
  @NotNull()
  public List<String> getIncludeFilters()
  {
    return includeFilters;
  }



  /**
   * Retrieves the list of search filters that may be used to identify which
   * entries should be excluded from the import.
   *
   * @return  The list of search filters that may be used to identify which
   *          entries should be excluded from the import, or an empty list if no
   *          entries should be excluded from the import based on their content.
   */
  @NotNull()
  public List<String> getExcludeFilters()
  {
    return excludeFilters;
  }



  /**
   * Retrieves the list of attributes that should be included in the imported
   * entries.
   *
   * @return  The list of attributes that should be included in the imported
   *          entries, or an empty list if no attributes should be excluded.
   */
  @NotNull()
  public List<String> getIncludeAttributes()
  {
    return includeAttributes;
  }



  /**
   * Retrieves the list of attributes that should be excluded from the imported
   * entries.
   *
   * @return  The list of attributes that should be excluded from the imported
   *          entries, or an empty list if no attributes should be excluded.
   */
  @NotNull()
  public List<String> getExcludeAttributes()
  {
    return excludeAttributes;
  }



  /**
   * Indicates whether the LDIF data to import is compressed.
   *
   * @return  {@code true} if the LDIF data to import is compressed, or
   *          {@code false} if not.
   */
  public boolean isCompressed()
  {
    return isCompressed;
  }



  /**
   * Indicates whether the LDIF data to import is encrypted.
   *
   * @return  {@code true} if the LDIF data to import is encrypted, or
   *          {@code false} if not.
   */
  public boolean isEncrypted()
  {
    return isEncrypted;
  }



  /**
   * Retrieves the path to a file that contains the passphrase to use to
   * generate the encryption key.
   *
   * @return  The path to a file that contains the passphrase to use to
   *          generate the encryption key, or {@code null} if the LDIF file is
   *          not encrypted or if the encryption key should be obtained through
   *          some other means.
   */
  @NotNull()
  public String getEncryptionPassphraseFile()
  {
    return encryptionPassphraseFile;
  }



  /**
   * Indicates whether the server should skip schema validation processing when
   * performing the import.
   *
   * @return  {@code true} if the server should skip schema validation
   *          processing when performing the import, or {@code false} if not.
   */
  public boolean skipSchemaValidation()
  {
    return skipSchemaValidation;
  }



  /**
   * Indicates whether the server should strip off any illegal trailing spaces
   * found in LDIF records rather than rejecting those records.
   *
   * @return  {@code true} if the server should strip off any illegal trailing
   *          spaces found in LDIF records, or {@code false} if it should reject
   *          any records containing illegal trailing spaces.
   */
  public boolean stripTrailingSpaces()
  {
    return stripTrailingSpaces;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_IMPORT_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(20);

    attrs.add(new Attribute(ATTR_LDIF_FILE, ldifFiles));
    attrs.add(new Attribute(ATTR_APPEND, String.valueOf(append)));
    attrs.add(new Attribute(ATTR_REPLACE_EXISTING,
                            String.valueOf(replaceExisting)));
    attrs.add(new Attribute(ATTR_OVERWRITE_REJECTS,
                            String.valueOf(overwriteRejects)));
    attrs.add(new Attribute(ATTR_CLEAR_BACKEND, String.valueOf(clearBackend)));
    attrs.add(new Attribute(ATTR_IS_COMPRESSED, String.valueOf(isCompressed)));
    attrs.add(new Attribute(ATTR_IS_ENCRYPTED, String.valueOf(isEncrypted)));
    attrs.add(new Attribute(ATTR_SKIP_SCHEMA_VALIDATION,
                            String.valueOf(skipSchemaValidation)));

    if (stripTrailingSpaces)
    {
      attrs.add(new Attribute(ATTR_STRIP_TRAILING_SPACES,
           String.valueOf(stripTrailingSpaces)));
    }

    if (backendID != null)
    {
      attrs.add(new Attribute(ATTR_BACKEND_ID, backendID));
    }

    if (rejectFile != null)
    {
      attrs.add(new Attribute(ATTR_REJECT_FILE, rejectFile));
    }

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

    if (encryptionPassphraseFile != null)
    {
      attrs.add(new Attribute(ATTR_ENCRYPTION_PASSPHRASE_FILE,
           encryptionPassphraseFile));
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
         PROPERTY_APPEND,
         PROPERTY_REPLACE_EXISTING,
         PROPERTY_REJECT_FILE,
         PROPERTY_OVERWRITE_REJECTS,
         PROPERTY_CLEAR_BACKEND,
         PROPERTY_INCLUDE_BRANCH,
         PROPERTY_EXCLUDE_BRANCH,
         PROPERTY_INCLUDE_FILTER,
         PROPERTY_EXCLUDE_FILTER,
         PROPERTY_INCLUDE_ATTRIBUTE,
         PROPERTY_EXCLUDE_ATTRIBUTE,
         PROPERTY_IS_COMPRESSED,
         PROPERTY_IS_ENCRYPTED,
         PROPERTY_ENCRYPTION_PASSPHRASE_FILE,
         PROPERTY_SKIP_SCHEMA_VALIDATION,
         PROPERTY_STRIP_TRAILING_SPACES);

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
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    if (backendID == null)
    {
      props.put(PROPERTY_BACKEND_ID, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_BACKEND_ID,
                Collections.<Object>singletonList(backendID));
    }

    props.put(PROPERTY_LDIF_FILE,
              Collections.<Object>unmodifiableList(ldifFiles));

    props.put(PROPERTY_APPEND,
              Collections.<Object>singletonList(append));

    props.put(PROPERTY_REPLACE_EXISTING,
              Collections.<Object>singletonList(replaceExisting));

    if (rejectFile == null)
    {
      props.put(PROPERTY_REJECT_FILE, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_REJECT_FILE,
                Collections.<Object>singletonList(rejectFile));
    }

    props.put(PROPERTY_OVERWRITE_REJECTS,
              Collections.<Object>singletonList(overwriteRejects));

    props.put(PROPERTY_CLEAR_BACKEND,
              Collections.<Object>singletonList(clearBackend));

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

    props.put(PROPERTY_IS_COMPRESSED,
              Collections.<Object>singletonList(isCompressed));

    props.put(PROPERTY_IS_ENCRYPTED,
              Collections.<Object>singletonList(isEncrypted));

    if (encryptionPassphraseFile == null)
    {
      props.put(PROPERTY_ENCRYPTION_PASSPHRASE_FILE, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_ENCRYPTION_PASSPHRASE_FILE,
         Collections.<Object>singletonList(encryptionPassphraseFile));
    }

    props.put(PROPERTY_SKIP_SCHEMA_VALIDATION,
              Collections.<Object>singletonList(skipSchemaValidation));

    props.put(PROPERTY_STRIP_TRAILING_SPACES,
              Collections.<Object>singletonList(stripTrailingSpaces));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
