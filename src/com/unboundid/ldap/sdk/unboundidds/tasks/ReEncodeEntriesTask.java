/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
 * This class defines a Directory Server task that can be used to cause entries
 * contained in a local DB backend to be re-encoded, which may be used to
 * apply any configuration changes that affect the encoding of that entry (e.g.,
 * if the entry should be encrypted, hashed, compressed, or fully or partially
 * uncached; or if these settings should be reverted).
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
 *   <LI>The backend ID of the backend in which entries should be re-encoded.
 *       This must be provided.</LI>
 *   <LI>The base DN of a branch of entries to include in the re-encode
 *       processing.</LI>
 *   <LI>The base DN of a branch of entries to exclude from the re-encode
 *       processing.</LI>
 *   <LI>A filter to use to identify entries to include in the re-encode
 *       processing.</LI>
 *   <LI>A filter to use to identify entries to exclude from the re-encode
 *       processing.</LI>
 *   <LI>The maximum rate at which to re-encode entries, in number of entries
 *       per second.</LI>
 *   <LI>An indication as to whether to skip entries that are fully
 *       uncached.</LI>
 *   <LI>An indication as to whether to skip entries that are partially
 *       uncached.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReEncodeEntriesTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the re-encode
   * entries task.
   */
  @NotNull static final String RE_ENCODE_ENTRIES_TASK_CLASS =
       "com.unboundid.directory.server.tasks.ReEncodeEntriesTask";


  /**
   * The name of the attribute used to specify the backend ID containing the
   * entries to re-encode.
   */
  @NotNull private static final String ATTR_BACKEND_ID =
       "ds-task-reencode-backend-id";


  /**
   * The name of the attribute used to specify the include branch(es).
   */
  @NotNull private static final String ATTR_INCLUDE_BRANCH =
       "ds-task-reencode-include-branch";


  /**
   * The name of the attribute used to specify the exclude branch(es).
   */
  @NotNull private static final String ATTR_EXCLUDE_BRANCH =
       "ds-task-reencode-exclude-branch";


  /**
   * The name of the attribute used to specify the include filter(s).
   */
  @NotNull private static final String ATTR_INCLUDE_FILTER =
       "ds-task-reencode-include-filter";


  /**
   * The name of the attribute used to specify the exclude filter(s).
   */
  @NotNull private static final String ATTR_EXCLUDE_FILTER =
       "ds-task-reencode-exclude-filter";


  /**
   * The name of the attribute used to specify the maximum re-encode rate in
   * entries per second.
   */
  @NotNull private static final String ATTR_MAX_ENTRIES_PER_SECOND =
       "ds-task-reencode-max-entries-per-second";


  /**
   * The name of the attribute used to specify whether to skip fully uncached
   * entries.
   */
  @NotNull private static final String ATTR_SKIP_FULLY_UNCACHED =
       "ds-task-reencode-skip-fully-uncached-entries";


  /**
   * The name of the attribute used to specify whether to skip partially
   * uncached entries.
   */
  @NotNull private static final String ATTR_SKIP_PARTIALLY_UNCACHED =
       "ds-task-reencode-skip-partially-uncached-entries";


  /**
   * The name of the object class used in re-encode entries task entries.
   */
  @NotNull private static final String OC_REENCODE_ENTRIES_TASK =
       "ds-task-reencode";


  /**
   * The task property that will be used for the backend ID.
   */
  @NotNull static final TaskProperty PROPERTY_BACKEND_ID =
       new TaskProperty(ATTR_BACKEND_ID,
            INFO_DISPLAY_NAME_REENCODE_BACKEND_ID.get(),
            INFO_DESCRIPTION_REENCODE_BACKEND_ID.get(),
          String.class, true, false, false);



  /**
   * The task property that will be used for the include branch(es).
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_BRANCH =
     new TaskProperty(ATTR_INCLUDE_BRANCH,
          INFO_DISPLAY_NAME_REENCODE_INCLUDE_BRANCH.get(),
          INFO_DESCRIPTION_REENCODE_INCLUDE_BRANCH.get(),
          String.class, false, true, false);



  /**
   * The task property that will be used for the exclude branch(es).
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_BRANCH =
     new TaskProperty(ATTR_EXCLUDE_BRANCH,
          INFO_DISPLAY_NAME_REENCODE_EXCLUDE_BRANCH.get(),
          INFO_DESCRIPTION_REENCODE_EXCLUDE_BRANCH.get(),
          String.class, false, true, false);



  /**
   * The task property that will be used for the include filter(s).
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_FILTER =
     new TaskProperty(ATTR_INCLUDE_FILTER,
          INFO_DISPLAY_NAME_REENCODE_INCLUDE_FILTER.get(),
          INFO_DESCRIPTION_REENCODE_INCLUDE_FILTER.get(),
          String.class, false, true, false);



  /**
   * The task property that will be used for the exclude filter(s).
   */
  @NotNull private static final TaskProperty PROPERTY_EXCLUDE_FILTER =
     new TaskProperty(ATTR_EXCLUDE_FILTER,
          INFO_DISPLAY_NAME_REENCODE_EXCLUDE_FILTER.get(),
          INFO_DESCRIPTION_REENCODE_EXCLUDE_FILTER.get(),
          String.class, false, true, false);



  /**
   * The task property that will be used for the maximum reencode rate.
   */
  @NotNull private static final TaskProperty PROPERTY_MAX_ENTRIES_PER_SECOND =
     new TaskProperty(ATTR_MAX_ENTRIES_PER_SECOND,
          INFO_DISPLAY_NAME_REENCODE_MAX_ENTRIES_PER_SECOND.get(),
          INFO_DESCRIPTION_REENCODE_MAX_ENTRIES_PER_SECOND.get(),
          Long.class, false, false, false);



  /**
   * The task property that will be used to indicate whether to skip fully
   * uncached entries.
   */
  @NotNull private static final TaskProperty PROPERTY_SKIP_FULLY_UNCACHED =
     new TaskProperty(ATTR_SKIP_FULLY_UNCACHED,
          INFO_DISPLAY_NAME_REENCODE_SKIP_FULLY_UNCACHED.get(),
          INFO_DESCRIPTION_REENCODE_SKIP_FULLY_UNCACHED.get(),
          Boolean.class, false, false, false);



  /**
   * The task property that will be used to indicate whether to skip partially
   * uncached entries.
   */
  @NotNull private static final TaskProperty PROPERTY_SKIP_PARTIALLY_UNCACHED =
     new TaskProperty(ATTR_SKIP_PARTIALLY_UNCACHED,
          INFO_DISPLAY_NAME_REENCODE_SKIP_PARTIALLY_UNCACHED.get(),
          INFO_DESCRIPTION_REENCODE_SKIP_PARTIALLY_UNCACHED.get(),
          Boolean.class, false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1804218099237094046L;



  // Indicates whether to skip fully-uncached entries.
  private final boolean skipFullyUncachedEntries;

  // Indicates whether to skip partially-uncached entries.
  private final boolean skipPartiallyUncachedEntries;

  // The maximum number of entries to re-encode per second.
  @Nullable private final Long maxEntriesPerSecond;

  // The list of exclude branch DNs.
  @NotNull private final List<String> excludeBranches;

  // The list of exclude filters.
  @NotNull private final List<String> excludeFilters;

  // The list of include branch DNs.
  @NotNull private final List<String> includeBranches;

  // The list of include filters.
  @NotNull private final List<String> includeFilters;

  // The backend ID for the backend containing entries to re-encode.
  @NotNull private final String backendID;



  /**
   * Creates a new uninitialized re-encode entries task instance which should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  public ReEncodeEntriesTask()
  {
    skipFullyUncachedEntries     = false;
    skipPartiallyUncachedEntries = false;
    maxEntriesPerSecond          = null;
    excludeBranches              = null;
    excludeFilters               = null;
    includeBranches              = null;
    includeFilters               = null;
    backendID                    = null;
  }



  /**
   * Creates a new re-encode entries task with the provided information.
   *
   * @param  taskID                        The task ID to use for this task.  If
   *                                       it is {@code null} then a UUID will
   *                                       be generated for use as the task ID.
   * @param  backendID                     The backend ID of the backend
   *                                       containing the entries to re-encode.
   *                                       It must not be {@code null}.
   * @param  includeBranches               A list containing the base DNs of
   *                                       branches to include in re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       include branches.
   * @param  excludeBranches               A list containing the base DNs of
   *                                       branches to exclude from re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       exclude branches.
   * @param  includeFilters                A list containing filters to use to
   *                                       identify entries to include in
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any include filters.
   * @param  excludeFilters                A list containing filters to use to
   *                                       identify entries to exclude from
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any exclude filters.
   * @param  maxEntriesPerSecond           The maximum number of entries to
   *                                       re-encode per second.  It may be
   *                                       {@code null} to indicate that no
   *                                       limit should be imposed.
   * @param  skipFullyUncachedEntries      Indicates whether to skip re-encode
   *                                       processing for entries that are fully
   *                                       uncached.
   * @param  skipPartiallyUncachedEntries  Indicates whether to skip re-encode
   *                                       processing for entries that contain
   *                                       a mix of cached and uncached
   *                                       attributes.
   */
  public ReEncodeEntriesTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final Long maxEntriesPerSecond,
              final boolean skipFullyUncachedEntries,
              final boolean skipPartiallyUncachedEntries)
  {
    this(taskID, backendID, includeBranches, excludeBranches, includeFilters,
         excludeFilters, maxEntriesPerSecond, skipFullyUncachedEntries,
         skipPartiallyUncachedEntries, null, null, null, null, null);
  }



  /**
   * Creates a new re-encode entries task with the provided information.
   *
   * @param  taskID                        The task ID to use for this task.  If
   *                                       it is {@code null} then a UUID will
   *                                       be generated for use as the task ID.
   * @param  backendID                     The backend ID of the backend
   *                                       containing the entries to re-encode.
   *                                       It must not be {@code null}.
   * @param  includeBranches               A list containing the base DNs of
   *                                       branches to include in re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       include branches.
   * @param  excludeBranches               A list containing the base DNs of
   *                                       branches to exclude from re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       exclude branches.
   * @param  includeFilters                A list containing filters to use to
   *                                       identify entries to include in
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any include filters.
   * @param  excludeFilters                A list containing filters to use to
   *                                       identify entries to exclude from
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any exclude filters.
   * @param  maxEntriesPerSecond           The maximum number of entries to
   *                                       re-encode per second.  It may be
   *                                       {@code null} to indicate that no
   *                                       limit should be imposed.
   * @param  skipFullyUncachedEntries      Indicates whether to skip re-encode
   *                                       processing for entries that are fully
   *                                       uncached.
   * @param  skipPartiallyUncachedEntries  Indicates whether to skip re-encode
   *                                       processing for entries that contain
   *                                       a mix of cached and uncached
   *                                       attributes.
   * @param  scheduledStartTime            The time that this task should start
   *                                       running.
   * @param  dependencyIDs                 The list of task IDs that will be
   *                                       required to complete before this task
   *                                       will be eligible to start.
   * @param  failedDependencyAction        Indicates what action should be taken
   *                                       if any of the dependencies for this
   *                                       task do not complete successfully.
   * @param  notifyOnCompletion            The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       when this task completes.
   * @param  notifyOnError                 The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       if this task does not complete
   *                                       successfully.
   */
  public ReEncodeEntriesTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final Long maxEntriesPerSecond,
              final boolean skipFullyUncachedEntries,
              final boolean skipPartiallyUncachedEntries,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, backendID, includeBranches, excludeBranches, includeFilters,
         excludeFilters, maxEntriesPerSecond, skipFullyUncachedEntries,
         skipPartiallyUncachedEntries, scheduledStartTime, dependencyIDs,
         failedDependencyAction, null, notifyOnCompletion, null,
         notifyOnError, null, null, null);
  }



  /**
   * Creates a new re-encode entries task with the provided information.
   *
   * @param  taskID                        The task ID to use for this task.  If
   *                                       it is {@code null} then a UUID will
   *                                       be generated for use as the task ID.
   * @param  backendID                     The backend ID of the backend
   *                                       containing the entries to re-encode.
   *                                       It must not be {@code null}.
   * @param  includeBranches               A list containing the base DNs of
   *                                       branches to include in re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       include branches.
   * @param  excludeBranches               A list containing the base DNs of
   *                                       branches to exclude from re-encode
   *                                       processing.  It may be {@code null}
   *                                       or empty if there should not be any
   *                                       exclude branches.
   * @param  includeFilters                A list containing filters to use to
   *                                       identify entries to include in
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any include filters.
   * @param  excludeFilters                A list containing filters to use to
   *                                       identify entries to exclude from
   *                                       re-encode processing.  It may be
   *                                       {@code null} or empty if there should
   *                                       not be any exclude filters.
   * @param  maxEntriesPerSecond           The maximum number of entries to
   *                                       re-encode per second.  It may be
   *                                       {@code null} to indicate that no
   *                                       limit should be imposed.
   * @param  skipFullyUncachedEntries      Indicates whether to skip re-encode
   *                                       processing for entries that are fully
   *                                       uncached.
   * @param  skipPartiallyUncachedEntries  Indicates whether to skip re-encode
   *                                       processing for entries that contain
   *                                       a mix of cached and uncached
   *                                       attributes.
   * @param  scheduledStartTime            The time that this task should start
   *                                       running.
   * @param  dependencyIDs                 The list of task IDs that will be
   *                                       required to complete before this task
   *                                       will be eligible to start.
   * @param  failedDependencyAction        Indicates what action should be taken
   *                                       if any of the dependencies for this
   *                                       task do not complete successfully.
   * @param  notifyOnStart                 The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       when this task starts running.
   * @param  notifyOnCompletion            The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       when this task completes.
   * @param  notifyOnSuccess               The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       if this task completes successfully.
   * @param  notifyOnError                 The list of e-mail addresses of
   *                                       individuals that should be notified
   *                                       if this task does not complete
   *                                       successfully.
   * @param  alertOnStart                  Indicates whether the server should
   *                                       send an alert notification when this
   *                                       task starts.
   * @param  alertOnSuccess                Indicates whether the server should
   *                                       send an alert notification if this
   *                                       task completes successfully.
   * @param  alertOnError                  Indicates whether the server should
   *                                       send an alert notification if this
   *                                       task fails to complete successfully.
   */
  public ReEncodeEntriesTask(@Nullable final String taskID,
              @NotNull final String backendID,
              @Nullable final List<String> includeBranches,
              @Nullable final List<String> excludeBranches,
              @Nullable final List<String> includeFilters,
              @Nullable final List<String> excludeFilters,
              @Nullable final Long maxEntriesPerSecond,
              final boolean skipFullyUncachedEntries,
              final boolean skipPartiallyUncachedEntries,
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
    super(taskID, RE_ENCODE_ENTRIES_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    Validator.ensureNotNull(backendID);

    this.backendID                    = backendID;
    this.maxEntriesPerSecond          = maxEntriesPerSecond;
    this.skipFullyUncachedEntries     = skipFullyUncachedEntries;
    this.skipPartiallyUncachedEntries = skipPartiallyUncachedEntries;

    if ((includeBranches == null) || includeBranches.isEmpty())
    {
      this.includeBranches = Collections.emptyList();
    }
    else
    {
      this.includeBranches = Collections.unmodifiableList(includeBranches);
    }

    if ((excludeBranches == null) || excludeBranches.isEmpty())
    {
      this.excludeBranches = Collections.emptyList();
    }
    else
    {
      this.excludeBranches = Collections.unmodifiableList(excludeBranches);
    }

    if ((includeFilters == null) || includeFilters.isEmpty())
    {
      this.includeFilters = Collections.emptyList();
    }
    else
    {
      this.includeFilters = Collections.unmodifiableList(includeFilters);
    }

    if ((excludeFilters == null) || excludeFilters.isEmpty())
    {
      this.excludeFilters = Collections.emptyList();
    }
    else
    {
      this.excludeFilters = Collections.unmodifiableList(excludeFilters);
    }
  }



  /**
   * Creates a new re-encode entries task from the provided entry.
   *
   * @param  entry  The entry to use to create this re-encode entries task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         re-encode entries task entry.
   */
  public ReEncodeEntriesTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the backend ID.  It must be present.
    backendID = entry.getAttributeValue(ATTR_BACKEND_ID);
    if (backendID == null)
    {
      throw new TaskException(ERR_REENCODE_TASK_MISSING_REQUIRED_ATTR.get(
           entry.getDN(), ATTR_BACKEND_ID));
    }

    // Get the set of include branches.
    final String[] iBranches = entry.getAttributeValues(ATTR_INCLUDE_BRANCH);
    if (iBranches == null)
    {
      includeBranches = Collections.emptyList();
    }
    else
    {
      includeBranches = Collections.unmodifiableList(Arrays.asList(iBranches));
    }

    // Get the set of exclude branches.
    final String[] eBranches = entry.getAttributeValues(ATTR_EXCLUDE_BRANCH);
    if (eBranches == null)
    {
      excludeBranches = Collections.emptyList();
    }
    else
    {
      excludeBranches = Collections.unmodifiableList(Arrays.asList(eBranches));
    }

    // Get the set of include filters.
    final String[] iFilters = entry.getAttributeValues(ATTR_INCLUDE_FILTER);
    if (iFilters == null)
    {
      includeFilters = Collections.emptyList();
    }
    else
    {
      includeFilters = Collections.unmodifiableList(Arrays.asList(iFilters));
    }

    // Get the set of exclude filters.
    final String[] eFilters = entry.getAttributeValues(ATTR_EXCLUDE_FILTER);
    if (eFilters == null)
    {
      excludeFilters = Collections.emptyList();
    }
    else
    {
      excludeFilters = Collections.unmodifiableList(Arrays.asList(eFilters));
    }

    // Get the max entry rate.
    maxEntriesPerSecond =
         entry.getAttributeValueAsLong(ATTR_MAX_ENTRIES_PER_SECOND);

    // Determine whether to skip fully uncached entries.
    final Boolean skipFullyUncached =
         entry.getAttributeValueAsBoolean(ATTR_SKIP_FULLY_UNCACHED);
    if (skipFullyUncached == null)
    {
      skipFullyUncachedEntries = false;
    }
    else
    {
      skipFullyUncachedEntries = skipFullyUncached;
    }

    // Determine whether to skip partially uncached entries.
    final Boolean skipPartiallyUncached =
         entry.getAttributeValueAsBoolean(ATTR_SKIP_PARTIALLY_UNCACHED);
    if (skipPartiallyUncached == null)
    {
      skipPartiallyUncachedEntries = false;
    }
    else
    {
      skipPartiallyUncachedEntries = skipPartiallyUncached;
    }
  }



  /**
   * Creates a new re-encode entries task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid re-encode entries task.
   */
  public ReEncodeEntriesTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(RE_ENCODE_ENTRIES_TASK_CLASS, properties);

    boolean      skipFullyUncached     = false;
    boolean      skipPartiallyUncached = false;
    Long         maxRate               = null;
    List<String> eBranches             = Collections.emptyList();
    List<String> eFilters              = Collections.emptyList();
    List<String> iBranches             = Collections.emptyList();
    List<String> iFilters              = Collections.emptyList();
    String       id                    = null;

    for (final Map.Entry<TaskProperty,List<Object>> e : properties.entrySet())
    {
      final TaskProperty p = e.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = e.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BACKEND_ID))
      {
        id = parseString(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_BRANCH))
      {
        final String[] branches = parseStrings(p, values, null);
        if (branches != null)
        {
          iBranches = Collections.unmodifiableList(Arrays.asList(branches));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_EXCLUDE_BRANCH))
      {
        final String[] branches = parseStrings(p, values, null);
        if (branches != null)
        {
          eBranches = Collections.unmodifiableList(Arrays.asList(branches));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_FILTER))
      {
        final String[] filters = parseStrings(p, values, null);
        if (filters != null)
        {
          iFilters = Collections.unmodifiableList(Arrays.asList(filters));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_EXCLUDE_FILTER))
      {
        final String[] filters = parseStrings(p, values, null);
        if (filters != null)
        {
          eFilters = Collections.unmodifiableList(Arrays.asList(filters));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_MAX_ENTRIES_PER_SECOND))
      {
        maxRate = parseLong(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SKIP_FULLY_UNCACHED))
      {
        skipFullyUncached = parseBoolean(p, values, false);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SKIP_PARTIALLY_UNCACHED))
      {
        skipPartiallyUncached = parseBoolean(p, values, false);
      }
    }

    if (id == null)
    {
      throw new TaskException(ERR_REENCODE_TASK_MISSING_REQUIRED_PROPERTY.get(
           ATTR_BACKEND_ID));
    }

    backendID                    = id;
    includeBranches              = iBranches;
    excludeBranches              = eBranches;
    includeFilters               = iFilters;
    excludeFilters               = eFilters;
    maxEntriesPerSecond          = maxRate;
    skipFullyUncachedEntries     = skipFullyUncached;
    skipPartiallyUncachedEntries = skipPartiallyUncached;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_REENCODE_ENTRIES.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_REENCODE_ENTRIES.get();
  }



  /**
   * Retrieves the backend ID for the backend containing the entries to
   * re-encode.
   *
   * @return  The backend ID for the backend containing the entries to
   *          re-encode.
   */
  @NotNull()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Retrieves the base DNs of the branches to include in re-encode processing,
   * if defined.
   *
   * @return  The base DNs of the branches to include in re-encode processing,
   *          or an empty list if there should not be any include branches.
   */
  @NotNull()
  public List<String> getIncludeBranches()
  {
    return includeBranches;
  }



  /**
   * Retrieves the base DNs of the branches to exclude from re-encode
   * processing, if defined.
   *
   * @return  The base DNs of the branches to exclude from re-encode processing,
   *          or an empty list if there should not be any exclude branches.
   */
  @NotNull()
  public List<String> getExcludeBranches()
  {
    return excludeBranches;
  }



  /**
   * Retrieves a set of filters to use to identify entries to include in
   * re-encode processing, if defined.
   *
   * @return  A set of filters to use to identify entries to include in
   *          re-encode processing, or an empty list if there should not be any
   *          include filters.
   */
  @NotNull()
  public List<String> getIncludeFilters()
  {
    return includeFilters;
  }



  /**
   * Retrieves a set of filters to use to identify entries to exclude from
   * re-encode processing, if defined.
   *
   * @return  A set of filters to use to identify entries to exclude from
   *          re-encode processing, or an empty list if there should not be any
   *          exclude filters.
   */
  @NotNull()
  public List<String> getExcludeFilters()
  {
    return excludeFilters;
  }



  /**
   * Retrieves the maximum number of entries that should be re-encoded per
   * second, if defined.
   *
   * @return  The maximum number of entries that should be re-encoded per
   *          second, or {@code null} if no rate limit should be imposed.
   */
  @Nullable()
  public Long getMaxEntriesPerSecond()
  {
    return maxEntriesPerSecond;
  }



  /**
   * Indicates whether to skip re-encode processing for entries that are stored
   * as fully uncached.
   *
   * @return  {@code true} if fully uncached entries should be skipped, or
   *          {@code false} if not.
   */
  public boolean skipFullyUncachedEntries()
  {
    return skipFullyUncachedEntries;
  }



  /**
   * Indicates whether to skip re-encode processing for entries that have a
   * mix of cached and uncached attributes.
   *
   * @return  {@code true} if partially uncached entries should be skipped, or
   *          {@code false} if not.
   */
  public boolean skipPartiallyUncachedEntries()
  {
    return skipPartiallyUncachedEntries;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_REENCODE_ENTRIES_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrList = new ArrayList<>(7);
    attrList.add(new Attribute(ATTR_BACKEND_ID, backendID));
    attrList.add(new Attribute(ATTR_SKIP_FULLY_UNCACHED,
         String.valueOf(skipFullyUncachedEntries)));
    attrList.add(new Attribute(ATTR_SKIP_PARTIALLY_UNCACHED,
         String.valueOf(skipPartiallyUncachedEntries)));

    if (! includeBranches.isEmpty())
    {
      attrList.add(new Attribute(ATTR_INCLUDE_BRANCH, includeBranches));
    }

    if (! excludeBranches.isEmpty())
    {
      attrList.add(new Attribute(ATTR_EXCLUDE_BRANCH, excludeBranches));
    }

    if (! includeFilters.isEmpty())
    {
      attrList.add(new Attribute(ATTR_INCLUDE_FILTER, includeFilters));
    }

    if (! excludeFilters.isEmpty())
    {
      attrList.add(new Attribute(ATTR_EXCLUDE_FILTER, excludeFilters));
    }

    if (maxEntriesPerSecond != null)
    {
      attrList.add(new Attribute(ATTR_MAX_ENTRIES_PER_SECOND,
           String.valueOf(maxEntriesPerSecond)));
    }

    return attrList;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(
         PROPERTY_BACKEND_ID,
         PROPERTY_INCLUDE_BRANCH,
         PROPERTY_EXCLUDE_BRANCH,
         PROPERTY_INCLUDE_FILTER,
         PROPERTY_EXCLUDE_FILTER,
         PROPERTY_MAX_ENTRIES_PER_SECOND,
         PROPERTY_SKIP_FULLY_UNCACHED,
         PROPERTY_SKIP_PARTIALLY_UNCACHED));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(15));

    props.put(PROPERTY_BACKEND_ID,
         Collections.<Object>singletonList(backendID));
    props.put(PROPERTY_INCLUDE_BRANCH,
         Collections.<Object>unmodifiableList(includeBranches));
    props.put(PROPERTY_EXCLUDE_BRANCH,
         Collections.<Object>unmodifiableList(excludeBranches));
    props.put(PROPERTY_INCLUDE_FILTER,
         Collections.<Object>unmodifiableList(includeFilters));
    props.put(PROPERTY_EXCLUDE_FILTER,
         Collections.<Object>unmodifiableList(excludeFilters));

    if (maxEntriesPerSecond == null)
    {
      props.put(PROPERTY_MAX_ENTRIES_PER_SECOND,
           Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_MAX_ENTRIES_PER_SECOND,
           Collections.<Object>singletonList(maxEntriesPerSecond));
    }

    props.put(PROPERTY_SKIP_FULLY_UNCACHED,
         Collections.<Object>singletonList(skipFullyUncachedEntries));
    props.put(PROPERTY_SKIP_PARTIALLY_UNCACHED,
         Collections.<Object>singletonList(skipPartiallyUncachedEntries));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
