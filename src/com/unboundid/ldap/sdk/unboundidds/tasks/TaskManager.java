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



import java.util.LinkedList;
import java.util.List;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class provides a number of utility methods for interacting with tasks in
 * Ping Identity, UnboundID, or Nokia/Alcatel-Lucent 8661 server instances.
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
 * It provides methods for the following:
 * <UL>
 *   <LI>Retrieving information about all scheduled, running, and
 *       recently-completed tasks in the server.</LI>
 *   <LI>Retrieving a specific task by its task ID.</LI>
 *   <LI>Scheduling a new task.</LI>
 *   <LI>Waiting for a scheduled task to complete.</LI>
 *   <LI>Canceling a scheduled task.</LI>
 *   <LI>Deleting a scheduled task.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process for retrieving information
 * about all tasks within the server and printing their contents using the
 * generic API:
 * <PRE>
 * List&lt;Task&gt; allTasks = TaskManager.getTasks(connection);
 * for (Task task : allTasks)
 * {
 *   String taskID = task.getTaskID();
 *   String taskName = task.getTaskName();
 *   TaskState taskState = task.getState();
 *   Map&lt;TaskProperty,List&lt;Object&gt;&gt; taskProperties =
 *        task.getTaskPropertyValues();
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TaskManager
{
  /**
   * Prevent this class from being instantiated.
   */
  private TaskManager()
  {
    // No implementation is required.
  }



  /**
   * Constructs the DN that should be used for the entry with the specified
   * task ID.
   *
   * @param  taskID  The task ID for which to construct the entry DN.
   *
   * @return  The constructed task entry DN.
   */
  @NotNull()
  private static String getTaskDN(@NotNull final String taskID)
  {
    // In general, constructing DNs is bad, but we'll do it here because we know
    // we're dealing specifically with the Ping Identity, UnboundID, or
    // Nokia/Alcatel-Lucent 8661 Directory Server and we can ensure that this
    // location will not change without extremely good reasons.
    return Task.ATTR_TASK_ID + '=' + taskID + ',' +
           Task.SCHEDULED_TASKS_BASE_DN;
  }



  /**
   * Retrieves the task with the specified task ID using the given connection.
   *
   * @param  connection  The connection to the Directory Server from which to
   *                     retrieve the task.  It must not be {@code null}.
   * @param  taskID      The task ID for the task to retrieve.  It must not be
   *                     {@code null}.
   *
   * @return  The requested task, or {@code null} if no such task exists in the
   *          server.  An attempt will be made to instantiate the task as the
   *          most appropriate task type, but if this is not possible then it
   *          will be a generic {@code Task} object.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server over the provided connection.
   *
   * @throws  TaskException  If the retrieved entry cannot be parsed as a task.
   */
  @Nullable()
  public static Task getTask(@NotNull final String taskID,
                             @NotNull final LDAPConnection connection)
         throws LDAPException, TaskException
  {
    try
    {
      final Entry taskEntry = connection.getEntry(getTaskDN(taskID));
      if (taskEntry == null)
      {
        return null;
      }

      return Task.decodeTask(taskEntry);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        return null;
      }

      throw le;
    }
  }



  /**
   * Retrieves all of the tasks defined in the Directory Server using the
   * provided connection.
   *
   * @param  connection  The connection to the Directory Server instance from
   *                     which to retrieve the defined tasks.
   *
   * @return  A list of all tasks defined in the associated Directory Server.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server over the provided connection.
   */
  @NotNull()
  public static List<Task> getTasks(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    final Filter filter =
         Filter.createEqualityFilter("objectClass", Task.OC_TASK);

    final SearchResult result = connection.search(Task.SCHEDULED_TASKS_BASE_DN,
         SearchScope.SUB, filter);

    final LinkedList<Task> tasks = new LinkedList<>();
    for (final SearchResultEntry e : result.getSearchEntries())
    {
      try
      {
        tasks.add(Task.decodeTask(e));
      }
      catch (final TaskException te)
      {
        Debug.debugException(te);

        // We got an entry that couldn't be parsed as a task.  This is an error,
        // but we don't want to spoil the ability to retrieve other tasks that
        // could be decoded, so we'll just ignore it for now.
      }
    }

    return tasks;
  }



  /**
   * Schedules a new instance of the provided task in the Directory Server.
   *
   * @param  task        The task to be scheduled.
   * @param  connection  The connection to the Directory Server in which the
   *                     task is to be scheduled.
   *
   * @return  A {@code Task} object representing the task that was scheduled and
   *          re-read from the server.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server, or if it rejects the task.
   *
   * @throws  TaskException  If the entry read back from the server after the
   *                         task was created could not be parsed as a task.
   */
  @NotNull()
  public static Task scheduleTask(@NotNull final Task task,
                                  @NotNull final LDAPConnection connection)
         throws LDAPException, TaskException
  {
    final Entry taskEntry = task.createTaskEntry();
    connection.add(task.createTaskEntry());

    final Entry newTaskEntry = connection.getEntry(taskEntry.getDN());
    if (newTaskEntry == null)
    {
      // This should never happen.
      throw new LDAPException(ResultCode.NO_SUCH_OBJECT);
    }

    return Task.decodeTask(newTaskEntry);
  }



  /**
   * Submits a request to cancel the task with the specified task ID.  Note that
   * some tasks may not support being canceled.  Further, for tasks that do
   * support being canceled it may take time for the cancel request to be
   * processed and for the task to actually be canceled.
   *
   * @param  taskID      The task ID of the task to be canceled.
   * @param  connection  The connection to the Directory Server in which to
   *                     perform the operation.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server.
   */
  public static void cancelTask(@NotNull final String taskID,
                                @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    // Note:  we should use the CANCELED_BEFORE_STARTING state when we want to
    // cancel a task regardless of whether it's pending or running.  If the
    // task is running, the server will convert it to STOPPED_BY_ADMINISTRATOR.
    final Modification mod =
         new Modification(ModificationType.REPLACE, Task.ATTR_TASK_STATE,
                          TaskState.CANCELED_BEFORE_STARTING.getName());
    connection.modify(getTaskDN(taskID), mod);
  }



  /**
   * Attempts to delete the task with the specified task ID.
   *
   * @param  taskID      The task ID of the task to be deleted.
   * @param  connection  The connection to the Directory Server in which to
   *                     perform the operation.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server.
   */
  public static void deleteTask(@NotNull final String taskID,
                                @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    connection.delete(getTaskDN(taskID));
  }



  /**
   * Waits for the specified task to complete.
   *
   * @param  taskID         The task ID of the task to poll.
   * @param  connection     The connection to the Directory Server containing
   *                        the desired task.
   * @param  pollFrequency  The minimum length of time in milliseconds between
   *                        checks to see if the task has completed.  A value
   *                        less than or equal to zero will cause the client to
   *                        check as quickly as possible.
   * @param  maxWaitTime    The maximum length of time in milliseconds to wait
   *                        for the task to complete before giving up.  A value
   *                        less than or equal to zero indicates that it will
   *                        keep checking indefinitely until the task has
   *                        completed.
   *
   * @return  Task  The decoded task after it has completed, or after the
   *                maximum wait time has expired.
   *
   * @throws  LDAPException  If a problem occurs while communicating with the
   *                         Directory Server.
   *
   * @throws  TaskException  If a problem occurs while attempting to parse the
   *                         task entry as a task, or if the specified task
   *                         entry could not be found.
   */
  @NotNull()
  public static Task waitForTask(@NotNull final String taskID,
                                 @NotNull final LDAPConnection connection,
                                 final long pollFrequency,
                                 final long maxWaitTime)
         throws LDAPException, TaskException
  {
    final long stopWaitingTime;
    if (maxWaitTime > 0)
    {
      stopWaitingTime = System.currentTimeMillis() + maxWaitTime;
    }
    else
    {
      stopWaitingTime = Long.MAX_VALUE;
    }

    while (true)
    {
      final Task t = getTask(taskID, connection);
      if (t == null)
      {
        throw new TaskException(ERR_TASK_MANAGER_WAIT_NO_SUCH_TASK.get(taskID));
      }

      if (t.isCompleted())
      {
        return t;
      }

      final long timeRemaining = stopWaitingTime - System.currentTimeMillis();
      if (timeRemaining <= 0)
      {
        return t;
      }

      try
      {
        Thread.sleep(Math.min(pollFrequency, timeRemaining));
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new TaskException(ERR_TASK_MANAGER_WAIT_INTERRUPTED.get(taskID),
                                ie);
      }
    }
  }
}
