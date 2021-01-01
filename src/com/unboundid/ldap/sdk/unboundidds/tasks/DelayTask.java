/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.DurationArgument;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that simply sleeps for a specified
 * length of time or until a given condition occurs.  It is primarily intended
 * to act as a separator between other tasks in a dependency chain.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DelayTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the delay task.
   */
  @NotNull static final String DELAY_TASK_CLASS =
       "com.unboundid.directory.server.tasks.DelayTask";



  /**
   * The name of the attribute used to specify the length of time that the
   * task should sleep.
   */
  @NotNull private static final String ATTR_SLEEP_DURATION =
       "ds-task-delay-sleep-duration";



  /**
   * The name of the task attribute that indicates whether to wait for the work
   * queue to become idle.
   */
  @NotNull private static final String ATTR_WAIT_FOR_WORK_QUEUE_IDLE =
       "ds-task-delay-duration-to-wait-for-work-queue-idle";



  /**
   * The name of the task attribute that provides a set of LDAP URLs to use to
   * issue searches that are expected to eventually return entries.
   */
  @NotNull private static final String ATTR_SEARCH_URL =
       "ds-task-delay-ldap-url-for-search-expected-to-return-entries";



  /**
   * The name of the task attribute that specifies the length of time between
   * searches.
   */
  @NotNull private static final String ATTR_SEARCH_INTERVAL =
       "ds-task-delay-search-interval";



  /**
   * The name of the task attribute that specifies the time limit for each
   * search.
   */
  @NotNull private static final String ATTR_SEARCH_TIME_LIMIT =
       "ds-task-delay-search-time-limit";



  /**
   * The name of the task attribute that specifies the total length of time to
   * wait for each search to return one or more entries.
   */
  @NotNull private static final String ATTR_SEARCH_DURATION =
       "ds-task-delay-duration-to-wait-for-search-to-return-entries";



  /**
   * The name of the task attribute that specifies the task return state to use
   * if a timeout is encountered during processing.
   */
  @NotNull private static final String ATTR_TIMEOUT_RETURN_STATE =
       "ds-task-delay-task-return-state-if-timeout-is-encountered";



  /**
   * The name of the object class used in delay task entries.
   */
  @NotNull private static final String OC_DELAY_TASK = "ds-task-delay";



  /**
   * The task property that will be used for the sleep duration.
   */
  @NotNull private static final TaskProperty PROPERTY_SLEEP_DURATION_MILLIS =
     new TaskProperty(ATTR_SLEEP_DURATION,
          INFO_DELAY_DISPLAY_NAME_SLEEP_DURATION.get(),
          INFO_DELAY_DESCRIPTION_SLEEP_DURATION.get(), Long.class, false,
          false, false);



  /**
   * The task property that will be used for the length of time to wait for the
   * work queue to report that the server is idle.
   */
  @NotNull private static final TaskProperty
       PROPERTY_WAIT_FOR_WORK_QUEUE_IDLE_MILLIS = new TaskProperty(
            ATTR_WAIT_FOR_WORK_QUEUE_IDLE,
            INFO_DELAY_DISPLAY_NAME_WAIT_FOR_WORK_QUEUE_IDLE.get(),
            INFO_DELAY_DESCRIPTION_WAIT_FOR_WORK_QUEUE_IDLE.get(), Long.class,
            false, false, false);



  /**
   * The task property that will be used to provide LDAP URLs for searches that
   * are expected to eventually return entries.
   */
  @NotNull private static final TaskProperty PROPERTY_SEARCH_URL =
     new TaskProperty(ATTR_SEARCH_URL,
          INFO_DELAY_DISPLAY_NAME_SEARCH_URL.get(),
          INFO_DELAY_DESCRIPTION_SEARCH_URL.get(), String.class, false, true,
          false);



  /**
   * The task property that will be used to specify the length of time between
   * searches.
   */
  @NotNull private static final TaskProperty PROPERTY_SEARCH_INTERVAL_MILLIS =
     new TaskProperty(ATTR_SEARCH_INTERVAL,
          INFO_DELAY_DISPLAY_NAME_SEARCH_INTERVAL.get(),
          INFO_DELAY_DESCRIPTION_SEARCH_INTERVAL.get(), Long.class, false,
          false, false);



  /**
   * The task property that will be used to specify the time limit for each
   * search.
   */
  @NotNull private static final TaskProperty PROPERTY_SEARCH_TIME_LIMIT_MILLIS =
     new TaskProperty(ATTR_SEARCH_TIME_LIMIT,
          INFO_DELAY_DISPLAY_NAME_SEARCH_TIME_LIMIT.get(),
          INFO_DELAY_DESCRIPTION_SEARCH_TIME_LIMIT.get(), Long.class, false,
          false, false);



  /**
   * The task property that will be used to specify the total length of time
   * allowed for a search to return entries.
   */
  @NotNull private static final TaskProperty PROPERTY_SEARCH_DURATION_MILLIS =
     new TaskProperty(ATTR_SEARCH_DURATION,
          INFO_DELAY_DISPLAY_NAME_SEARCH_DURATION.get(),
          INFO_DELAY_DESCRIPTION_SEARCH_DURATION.get(), Long.class, false,
          false, false);



  /**
   * The task property that will be used for the task return state if a timeout
   * is encountered.
   */
  @NotNull private static final TaskProperty PROPERTY_TIMEOUT_RETURN_STATE =
     new TaskProperty(ATTR_TIMEOUT_RETURN_STATE,
          INFO_DELAY_DISPLAY_NAME_TIMEOUT_RETURN_STATE.get(),
          INFO_DELAY_DESCRIPTION_TIMEOUT_RETURN_STATE.get(),
          String.class, false, false, false,
          new String[]
          {
            "STOPPED_BY_ERROR",
            "STOPPED-BY-ERROR",
            "COMPLETED_WITH_ERRORS",
            "COMPLETED-WITH-ERRORS",
            "COMPLETED_SUCCESSFULLY",
            "COMPLETED-SUCCESSFULLY"
          });



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -639870096358259180L;



  // A list of LDAP URLs that define searches that are expected to return
  // entries.
  @NotNull private final List<LDAPURL>
       ldapURLsForSearchesExpectedToReturnEntries;

  // The length of time, in milliseconds, between each search.
  @Nullable private final Long millisBetweenSearches;

  // The maximum length of time, in milliseconds, that the task should wait for
  // the work queue to report that the server is idle.
  @Nullable private final Long millisToWaitForWorkQueueToBecomeIdle;

  // The maximum length of time, in milliseconds, to wait for a response to
  // each search.
  @Nullable private final Long searchTimeLimitMillis;

  // The length of time, in milliseconds, that the task should sleep.
  @Nullable private final Long sleepDurationMillis;

  // The maximum length of time, in milliseconds, to wait for each search to
  // return at least one entry.
  @Nullable private final Long totalDurationMillisForEachLDAPURL;

  // The task state that should be returned if a timeout is encountered during
  // task processing.
  @Nullable private final String taskStateIfTimeoutIsEncountered;



  /**
   * Creates a new, uninitialized delay task instance that should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public DelayTask()
  {
    ldapURLsForSearchesExpectedToReturnEntries = null;
    millisBetweenSearches = null;
    millisToWaitForWorkQueueToBecomeIdle = null;
    searchTimeLimitMillis = null;
    sleepDurationMillis = null;
    totalDurationMillisForEachLDAPURL = null;
    taskStateIfTimeoutIsEncountered = null;
  }



  /**
   * Creates a new delay task with the provided information.
   *
   * @param  sleepDurationMillis
   *             The length of time, in milliseconds, that the task should
   *             sleep.  This may be {@code null} if the task is intended to
   *             wait for the work queue to become idle or searches to return
   *             entries and no additional sleep is required.  If it is not
   *             {@code null}, then it must be greater than zero.  If a sleep
   *             duration is provided and the task should also wait for the work
   *             queue to become idle or wait for search results, then the sleep
   *             for this duration will occur after waiting for those other
   *             conditions to be satisfied (or for a timeout to occur).
   * @param  millisToWaitForWorkQueueToBecomeIdle
   *              The length of time, in milliseconds, that the task should wait
   *              for the server work queue to report that there are no pending
   *              requests and all worker threads are idle.  This may be
   *              {@code null} if the task should not wait for the work queue to
   *              become idle.  If it is not {@code null}, then it must be
   *              greater than zero.
   * @param  ldapURLsForSearchesExpectedToReturnEntries
   *              A list of LDAP URLs that provide criteria for search requests
   *              that are eventually expected to return one or more entries.
   *              This may be {@code null} or empty if the task should not
   *              perform any such searches.  If this is non-empty, then the
   *              {@code millisBetweenSearches},
   *              {@code searchTimeLimitMillis}, and
   *              {@code totalDurationMillisForEachLDAPURL} arguments must be
   *              non-{@code null}.
   * @param  millisBetweenSearches
   *              The length of time, in milliseconds, between the individual
   *              searches created from each of the provided LDAP URLs.  Each
   *              search created from an LDAP URL will be repeated until it
   *              returns at least one entry, or until the total length of time
   *              processing that search meets or exceeds the value of the
   *              {@code totalDurationMillisForEachSearch} argument.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is not
   *              empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  searchTimeLimitMillis
   *              The maximum length of time, in milliseconds, to wait for a
   *              response to each individual search created from one of the
   *              provided LDAP URLs.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is
   *              not empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  totalDurationMillisForEachLDAPURL
   *              The maximum length of time, in milliseconds, to wait for the
   *              search criteria created from each of the provided LDAP URLs
   *              to match at least one entry.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is
   *              not empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  taskStateIfTimeoutIsEncountered
   *              The task state that should be used if a timeout is encountered
   *              while waiting for the work queue to become idle or while
   *              waiting for search criteria created from an LDAP URL to match
   *              at least one entry.  This may be {@code null} to indicate that
   *              the server should determine the appropriate task state.  If it
   *              is non-{@code null}, then the value must be one of
   *              {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public DelayTask(@Nullable final Long sleepDurationMillis,
       @Nullable final Long millisToWaitForWorkQueueToBecomeIdle,
       @Nullable final Collection<LDAPURL>
            ldapURLsForSearchesExpectedToReturnEntries,
       @Nullable final Long millisBetweenSearches,
       @Nullable final Long searchTimeLimitMillis,
       @Nullable final Long totalDurationMillisForEachLDAPURL,
       @Nullable final TaskState taskStateIfTimeoutIsEncountered)
       throws TaskException
  {
    this(null, sleepDurationMillis, millisToWaitForWorkQueueToBecomeIdle,
         ldapURLsForSearchesExpectedToReturnEntries, millisBetweenSearches,
         searchTimeLimitMillis, totalDurationMillisForEachLDAPURL,
         taskStateIfTimeoutIsEncountered, null, null, null, null, null, null,
         null, null, null, null);
  }



  /**
   * Creates a new delay task with the provided information.
   *
   * @param  taskID
   *              The task ID to use for this task.  If it is {@code null} then
   *              a UUID will be generated for use as the task ID.
   * @param  sleepDurationMillis
   *             The length of time, in milliseconds, that the task should
   *             sleep.  This may be {@code null} if the task is intended to
   *             wait for the work queue to become idle or searches to return
   *             entries and no additional sleep is required.  If it is not
   *             {@code null}, then it must be greater than zero.  If a sleep
   *             duration is provided and the task should also wait for the work
   *             queue to become idle or wait for search results, then the sleep
   *             for this duration will occur after waiting for those other
   *             conditions to be satisfied (or for a timeout to occur).
   * @param  millisToWaitForWorkQueueToBecomeIdle
   *              The length of time, in milliseconds, that the task should wait
   *              for the server work queue to report that there are no pending
   *              requests and all worker threads are idle.  This may be
   *              {@code null} if the task should not wait for the work queue to
   *              become idle.  If it is not {@code null}, then it must be
   *              greater than zero.
   * @param  ldapURLsForSearchesExpectedToReturnEntries
   *              A list of LDAP URLs that provide criteria for search requests
   *              that are eventually expected to return one or more entries.
   *              This may be {@code null} or empty if the task should not
   *              perform any such searches.  If this is non-empty, then the
   *              {@code millisBetweenSearches},
   *              {@code searchTimeLimitMillis}, and
   *              {@code totalDurationMillisForEachLDAPURL} arguments must be
   *              non-{@code null}.
   * @param  millisBetweenSearches
   *              The length of time, in milliseconds, between the individual
   *              searches created from each of the provided LDAP URLs.  Each
   *              search created from an LDAP URL will be repeated until it
   *              returns at least one entry, or until the total length of time
   *              processing that search meets or exceeds the value of the
   *              {@code totalDurationMillisForEachSearch} argument.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is not
   *              empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  searchTimeLimitMillis
   *              The maximum length of time, in milliseconds, to wait for a
   *              response to each individual search created from one of the
   *              provided LDAP URLs.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is
   *              not empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  totalDurationMillisForEachLDAPURL
   *              The maximum length of time, in milliseconds, to wait for the
   *              search criteria created from each of the provided LDAP URLs
   *              to match at least one entry.  If the
   *              {@code ldapURLsForSearchesExpectedToReturnEntries} list is
   *              not empty, then this must not be {@code null}.  If it is not
   *              {@code null}, then it must be greater than zero.
   * @param  taskStateIfTimeoutIsEncountered
   *              The task state that should be used if a timeout is encountered
   *              while waiting for the work queue to become idle or while
   *              waiting for search criteria created from an LDAP URL to match
   *              at least one entry.  This may be {@code null} to indicate that
   *              the server should determine the appropriate task state.  If it
   *              is non-{@code null}, then the value must be one of
   *              {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   * @param  scheduledStartTime
   *              The time that this task should start running.
   * @param  dependencyIDs
   *              The list of task IDs that will be required to complete before
   *              this task will be eligible to start.
   * @param  failedDependencyAction
   *              Indicates what action should be taken if any of the
   *              dependencies for this task do not complete successfully.
   * @param  notifyOnStart
   *              The list of e-mail addresses of individuals that should be
   *              notified when this task starts.
   * @param  notifyOnCompletion
   *              The list of e-mail addresses of individuals that should be
   *              notified when this task completes.
   * @param  notifyOnSuccess
   *              The list of e-mail addresses of individuals that should be
   *              notified if this task completes successfully.
   * @param  notifyOnError
   *              The list of e-mail addresses of individuals that should be
   *              notified if this task does not complete successfully.
   * @param  alertOnStart
   *              Indicates whether the server should send an alert notification
   *              when this task starts.
   * @param  alertOnSuccess
   *              Indicates whether the server should send an alert notification
   *              if this task completes successfully.
   * @param  alertOnError
   *              Indicates whether the server should send an alert notification
   *              if this task fails to complete successfully.
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public DelayTask(@Nullable final String taskID,
       @Nullable final Long sleepDurationMillis,
       @Nullable final Long millisToWaitForWorkQueueToBecomeIdle,
       @Nullable final Collection<LDAPURL>
            ldapURLsForSearchesExpectedToReturnEntries,
       @Nullable final Long millisBetweenSearches,
       @Nullable final Long searchTimeLimitMillis,
       @Nullable final Long totalDurationMillisForEachLDAPURL,
       @Nullable final TaskState taskStateIfTimeoutIsEncountered,
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
       throws TaskException
  {
    super(taskID, DELAY_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    this.sleepDurationMillis = sleepDurationMillis;
    this.millisToWaitForWorkQueueToBecomeIdle =
         millisToWaitForWorkQueueToBecomeIdle;
    this.millisBetweenSearches = millisBetweenSearches;
    this.searchTimeLimitMillis = searchTimeLimitMillis;
    this.totalDurationMillisForEachLDAPURL = totalDurationMillisForEachLDAPURL;

    if (ldapURLsForSearchesExpectedToReturnEntries == null)
    {
      this.ldapURLsForSearchesExpectedToReturnEntries = Collections.emptyList();
    }
    else
    {
      this.ldapURLsForSearchesExpectedToReturnEntries =
           Collections.unmodifiableList(
                new ArrayList<>(ldapURLsForSearchesExpectedToReturnEntries));
    }

    if (taskStateIfTimeoutIsEncountered == null)
    {
      this.taskStateIfTimeoutIsEncountered = null;
    }
    else
    {
      switch (taskStateIfTimeoutIsEncountered)
      {
        case STOPPED_BY_ERROR:
        case COMPLETED_WITH_ERRORS:
        case COMPLETED_SUCCESSFULLY:
          this.taskStateIfTimeoutIsEncountered =
               taskStateIfTimeoutIsEncountered.name();
          break;
        default:
          throw new TaskException(
               ERR_DELAY_INVALID_TIMEOUT_STATE.get(
                    TaskState.STOPPED_BY_ERROR.name(),
                    TaskState.COMPLETED_WITH_ERRORS.name(),
                    TaskState.COMPLETED_SUCCESSFULLY.name()));
      }
    }

    if ((sleepDurationMillis != null) && (sleepDurationMillis <= 0L))
    {
      throw new TaskException(ERR_DELAY_INVALID_SLEEP_DURATION.get());
    }

    if ((millisToWaitForWorkQueueToBecomeIdle != null) &&
       (millisToWaitForWorkQueueToBecomeIdle <= 0L))
    {
      throw new TaskException(ERR_DELAY_INVALID_WAIT_FOR_QUEUE_IDLE.get());
    }

    if ((millisBetweenSearches != null) && (millisBetweenSearches <= 0L))
    {
      throw new TaskException(ERR_DELAY_INVALID_SEARCH_INTERVAL.get());
    }

    if ((searchTimeLimitMillis != null) && (searchTimeLimitMillis <= 0L))
    {
      throw new TaskException(ERR_DELAY_INVALID_SEARCH_TIME_LIMIT.get());
    }

    if ((totalDurationMillisForEachLDAPURL != null) &&
         (totalDurationMillisForEachLDAPURL <= 0L))
    {
      throw new TaskException(ERR_DELAY_INVALID_SEARCH_DURATION.get());
    }

    if (! this.ldapURLsForSearchesExpectedToReturnEntries.isEmpty())
    {
      if ((millisBetweenSearches == null) ||
           (searchTimeLimitMillis == null) ||
           (totalDurationMillisForEachLDAPURL == null))
      {
        throw new TaskException(ERR_DELAY_URL_WITHOUT_REQUIRED_PARAM.get());
      }

      if (millisBetweenSearches >= totalDurationMillisForEachLDAPURL)
      {
        throw new TaskException(ERR_DELAY_INVALID_SEARCH_INTERVAL.get());
      }

      if (searchTimeLimitMillis >= totalDurationMillisForEachLDAPURL)
      {
        throw new TaskException(ERR_DELAY_INVALID_SEARCH_TIME_LIMIT.get());
      }
    }
  }



  /**
   * Creates a new delay task from the provided entry.
   *
   * @param  entry  The entry to use to create this delay task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as an delay
   *                         task entry.
   */
  public DelayTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the name of the task state to use if a timeout occurs during task
    // processing.
    taskStateIfTimeoutIsEncountered =
         entry.getAttributeValue(ATTR_TIMEOUT_RETURN_STATE);


    // Parse the duration attributes.
    sleepDurationMillis = parseDuration(entry, ATTR_SLEEP_DURATION);
    millisToWaitForWorkQueueToBecomeIdle =
         parseDuration(entry,ATTR_WAIT_FOR_WORK_QUEUE_IDLE);
    millisBetweenSearches = parseDuration(entry, ATTR_SEARCH_INTERVAL);
    searchTimeLimitMillis = parseDuration(entry, ATTR_SEARCH_TIME_LIMIT);
    totalDurationMillisForEachLDAPURL =
         parseDuration(entry, ATTR_SEARCH_DURATION);


    // Parse the set of LDAP URLs.
    final String[] urlStrings = entry.getAttributeValues(ATTR_SEARCH_URL);
    if (urlStrings == null)
    {
      ldapURLsForSearchesExpectedToReturnEntries = Collections.emptyList();
    }
    else
    {
      final ArrayList<LDAPURL> urls = new ArrayList<>(urlStrings.length);
      for (final String s : urlStrings)
      {
        try
        {
          urls.add(new LDAPURL(s));
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new TaskException(
               ERR_DELAY_ENTRY_MALFORMED_URL.get(ATTR_SEARCH_URL, s,
                    e.getMessage()),
               e);
        }
      }

      ldapURLsForSearchesExpectedToReturnEntries =
           Collections.unmodifiableList(urls);
    }
  }



  /**
   * Retrieves the value of the specified attribute from the given entry and
   * parses its value as a duration.
   *
   * @param  entry          The entry from which to retrieve the attribute.
   * @param  attributeName  The name of the attribute containing the value to
   *                        parse.  It must not be {@code null}.
   *
   * @return  The number of milliseconds in the duration represented by the
   *          value of the specified attribute, or {@code null} if the attribute
   *          was not present in the entry.
   *
   * @throws  TaskException  If the attribute value cannot be parsed as a
   *                         duration.
   */
  @Nullable()
  private static Long parseDuration(@NotNull final Entry entry,
                                    @NotNull final String attributeName)
          throws TaskException
  {
    final String value = entry.getAttributeValue(attributeName);
    if (value == null)
    {
      return null;
    }

    try
    {
      return DurationArgument.parseDuration(value, TimeUnit.MILLISECONDS);
    }
    catch (final ArgumentException e)
    {
      throw new TaskException(
           ERR_DELAY_CANNOT_PARSE_ATTR_VALUE_AS_DURATION.get(attributeName,
                e.getMessage()),
           e);
    }
  }



  /**
   * Creates a new delay task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid delay task.
   */
  public DelayTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(DELAY_TASK_CLASS, properties);

    Long searchDuration = null;
    Long searchInterval = null;
    Long searchTimeLimit = null;
    Long sleepDuration = null;
    Long workQueueWaitTime = null;
    String timeoutReturnState = null;
    final List<LDAPURL> urls = new ArrayList<>(10);
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = StaticUtils.toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();
      switch (attrName)
      {
        case ATTR_SLEEP_DURATION:
          sleepDuration = parseLong(p, values, null);
          break;
        case ATTR_WAIT_FOR_WORK_QUEUE_IDLE:
          workQueueWaitTime = parseLong(p, values, null);
          break;
        case ATTR_SEARCH_URL:
          for (final String urlString :
               parseStrings(p, values, StaticUtils.NO_STRINGS))
          {
            try
            {
              urls.add(new LDAPURL(urlString));
            }
            catch (final LDAPException e)
            {
              Debug.debugException(e);
              throw new TaskException(
                   ERR_DELAY_ENTRY_MALFORMED_URL.get(ATTR_SEARCH_URL, urlString,
                        e.getMessage()),
                   e);
            }
          }
          break;
        case ATTR_SEARCH_INTERVAL:
          searchInterval = parseLong(p, values, null);
          break;
        case ATTR_SEARCH_TIME_LIMIT:
          searchTimeLimit = parseLong(p, values, null);
          break;
        case ATTR_SEARCH_DURATION:
          searchDuration = parseLong(p, values, null);
          break;
        case ATTR_TIMEOUT_RETURN_STATE:
          timeoutReturnState = parseString(p, values, null);
          break;
      }
    }

    sleepDurationMillis = sleepDuration;
    millisToWaitForWorkQueueToBecomeIdle = workQueueWaitTime;
    ldapURLsForSearchesExpectedToReturnEntries =
         Collections.unmodifiableList(urls);
    millisBetweenSearches = searchInterval;
    searchTimeLimitMillis = searchTimeLimit;
    totalDurationMillisForEachLDAPURL = searchDuration;
    taskStateIfTimeoutIsEncountered = timeoutReturnState;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_DELAY.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_DELAY.get();
  }



  /**
   * Retrieves the length of time, in milliseconds, that the task should sleep.
   *
   * @return  The length of time, in milliseconds, that the task should sleep,
   *          or {@code null} if the task should not sleep for a specified
   *          period of time.
   */
  @Nullable()
  public Long getSleepDurationMillis()
  {
    return sleepDurationMillis;
  }



  /**
   * Retrieves the length of time, in milliseconds, that the task should wait
   * for the server work queue to report that there are no pending requests and
   * all worker threads are idle.
   *
   * @return  The length of time, in milliseconds, that the task should wait for
   *          the server work queue to report that it is idle, or {@code null}
   *          if the task should not wait for the work queue to be idle
   */
  @Nullable()
  public Long getMillisToWaitForWorkQueueToBecomeIdle()
  {
    return millisToWaitForWorkQueueToBecomeIdle;
  }



  /**
   * Retrieves a list of LDAP URLs that provide criteria for search requests
   * that are eventually expected to return one or more entries.
   *
   * @return  A list of LDAP URLs that provide criteria for search requests that
   *          are eventually expected to return one or more entries, or an empty
   *          list if no searches are to be performed.
   */
  @NotNull()
  public List<LDAPURL> getLDAPURLsForSearchesExpectedToReturnEntries()
  {
    return ldapURLsForSearchesExpectedToReturnEntries;
  }



  /**
   * Retrieves the length of time, in milliseconds, between the individual
   * searches created from each of the provided LDAP URLs.  Each search created
   * from an LDAP URL will be repeated until it returns at least one entry, or
   * until the total length of processing that search meets or exceeds the value
   * returned by the {@link #getTotalDurationMillisForEachLDAPURL()} method.
   *
   * @return  The length of time, in milliseconds, between the individual
   *          searches created from each of the provided LDAP URLs, or
   *          {@code null} if no searches are to be performed.
   */
  @Nullable()
  public Long getMillisBetweenSearches()
  {
    return millisBetweenSearches;
  }



  /**
   * Retrieves the maximum length of time, in milliseconds, to wait for a
   * response to each individual search created from one of the provided LDAP
   * URLs.
   *
   * @return  The maximum length of time, in milliseconds, to wait for a
   *          response to each individual search created from one of the
   *          provided LDAP URLs, or {@code null} if no searches are to be
   *          performed.
   */
  @Nullable()
  public Long getSearchTimeLimitMillis()
  {
    return searchTimeLimitMillis;
  }



  /**
   * Retrieves the maximum length of time, in milliseconds, to wait for the
   * search criteria created from each of the provided LDAP URLs to match at
   * least one entry.
   *
   * @return  The maximum length of time, in milliseconds, to wait for the
   *          search criteria created from each of the provided LDAP URLs to
   *          match at least one entry, or {@code null} if no searches are to be
   *          performed.
   */
  @Nullable()
  public Long getTotalDurationMillisForEachLDAPURL()
  {
    return totalDurationMillisForEachLDAPURL;
  }



  /**
   * Retrieves the name of the task state that should be used if a timeout is
   * encountered while waiting for the work queue to become idle or while
   * waiting for search criteria created from an LDAP URL to match at least one
   * entry.
   *
   * @return  The name of the task state that should be used if a timeout is
   *          encountered, or {@code null} if the server should determine the
   *          appropriate task state.
   */
  @Nullable()
  public String getTaskStateIfTimeoutIsEncountered()
  {
    return taskStateIfTimeoutIsEncountered;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_DELAY_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final LinkedList<Attribute> attrList = new LinkedList<>();

    if (sleepDurationMillis != null)
    {
      final long sleepDurationNanos = sleepDurationMillis * 1_000_000L;
      attrList.add(new Attribute(ATTR_SLEEP_DURATION,
           DurationArgument.nanosToDuration(sleepDurationNanos)));
    }

    if (millisToWaitForWorkQueueToBecomeIdle != null)
    {
      final long waitTimeNanos =
           millisToWaitForWorkQueueToBecomeIdle * 1_000_000L;
      attrList.add(new Attribute(ATTR_WAIT_FOR_WORK_QUEUE_IDLE,
           DurationArgument.nanosToDuration(waitTimeNanos)));
    }

    if (! ldapURLsForSearchesExpectedToReturnEntries.isEmpty())
    {
      final ArrayList<String> urlStrings =
           new ArrayList<>(ldapURLsForSearchesExpectedToReturnEntries.size());
      for (final LDAPURL url : ldapURLsForSearchesExpectedToReturnEntries)
      {
        urlStrings.add(url.toString());
      }

      attrList.add(new Attribute(ATTR_SEARCH_URL, urlStrings));
    }

    if (millisBetweenSearches != null)
    {
      final long intervalNanos = millisBetweenSearches * 1_000_000L;
      attrList.add(new Attribute(ATTR_SEARCH_INTERVAL,
           DurationArgument.nanosToDuration(intervalNanos)));
    }

    if (searchTimeLimitMillis != null)
    {
      final long timeLimitNanos = searchTimeLimitMillis * 1_000_000L;
      attrList.add(new Attribute(ATTR_SEARCH_TIME_LIMIT,
           DurationArgument.nanosToDuration(timeLimitNanos)));
    }

    if (totalDurationMillisForEachLDAPURL != null)
    {
      final long durationNanos = totalDurationMillisForEachLDAPURL * 1_000_000L;
      attrList.add(new Attribute(ATTR_SEARCH_DURATION,
           DurationArgument.nanosToDuration(durationNanos)));
    }

    if (taskStateIfTimeoutIsEncountered != null)
    {
      attrList.add(new Attribute(ATTR_TIMEOUT_RETURN_STATE,
           taskStateIfTimeoutIsEncountered));
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
         PROPERTY_SLEEP_DURATION_MILLIS,
         PROPERTY_WAIT_FOR_WORK_QUEUE_IDLE_MILLIS,
         PROPERTY_SEARCH_URL,
         PROPERTY_SEARCH_INTERVAL_MILLIS,
         PROPERTY_SEARCH_TIME_LIMIT_MILLIS,
         PROPERTY_SEARCH_DURATION_MILLIS,
         PROPERTY_TIMEOUT_RETURN_STATE));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty, List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(7));

    if (sleepDurationMillis != null)
    {
      props.put(PROPERTY_SLEEP_DURATION_MILLIS,
           Collections.<Object>singletonList(sleepDurationMillis));
    }

    if (millisToWaitForWorkQueueToBecomeIdle != null)
    {
      props.put(PROPERTY_WAIT_FOR_WORK_QUEUE_IDLE_MILLIS,
           Collections.<Object>singletonList(
                millisToWaitForWorkQueueToBecomeIdle));
    }

    if (! ldapURLsForSearchesExpectedToReturnEntries.isEmpty())
    {
      final List<String> urlStrings =
           new ArrayList<>(ldapURLsForSearchesExpectedToReturnEntries.size());
      for (final LDAPURL url : ldapURLsForSearchesExpectedToReturnEntries)
      {
        urlStrings.add(url.toString());
      }
      props.put(PROPERTY_SEARCH_URL,

           Collections.<Object>unmodifiableList(urlStrings));
    }

    if (millisBetweenSearches != null)
    {
      props.put(PROPERTY_SEARCH_INTERVAL_MILLIS,
           Collections.<Object>singletonList(millisBetweenSearches));
    }

    if (searchTimeLimitMillis != null)
    {
      props.put(PROPERTY_SEARCH_TIME_LIMIT_MILLIS,
           Collections.<Object>singletonList(searchTimeLimitMillis));
    }

    if (totalDurationMillisForEachLDAPURL != null)
    {
      props.put(PROPERTY_SEARCH_DURATION_MILLIS,
           Collections.<Object>singletonList(
                totalDurationMillisForEachLDAPURL));
    }

    if (taskStateIfTimeoutIsEncountered != null)
    {
      props.put(PROPERTY_TIMEOUT_RETURN_STATE,
           Collections.<Object>singletonList(taskStateIfTimeoutIsEncountered));
    }

    return Collections.unmodifiableMap(props);
  }
}
