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

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to cause the
 * server to leave lockdown mode and resume normal operation.  Note that because
 * of the nature of lockdown mode, it this task may only be requested by a user
 * with the lockdown-mode privilege.  Alternately, the server may be restarted
 * and it will not be placed in lockdown mode at startup unless a significant
 * problem is encountered in which there may be a risk of unauthorized access to
 * data.
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
 * The leave lockdown mode task does not have any task-specific properties.  See
 * the {@link EnterLockdownModeTask} class for more information about lockdown
 * mode and a task that may be used to force the server to enter this state.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LeaveLockdownModeTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the leave
   * lockdown mode task.
   */
  @NotNull static final String LEAVE_LOCKDOWN_MODE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.LeaveLockdownModeTask";



  /**
   * The name of the attribute used to specify the reason for taking the server
   * out of lockdown mode.
   */
  @NotNull private static final String ATTR_LEAVE_LOCKDOWN_REASON =
       "ds-task-leave-lockdown-reason";



  /**
   * The task property for the leave-lockdown reason.
   */
  @NotNull private static final TaskProperty PROPERTY_LEAVE_LOCKDOWN_REASON =
       new TaskProperty(ATTR_LEAVE_LOCKDOWN_REASON,
                        INFO_DISPLAY_NAME_LEAVE_LOCKDOWN_REASON.get(),
                        INFO_DESCRIPTION_LEAVE_LOCKDOWN_REASON.get(),
                        String.class, false, false, false);



  /**
   * The name of the object class used in leave-lockdown-mode task entries.
   */
  @NotNull private static final String OC_LEAVE_LOCKDOWN_MODE_TASK =
      "ds-task-leave-lockdown-mode";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1353712468653879793L;



  // The reason for leaving lockdown mode.
  @Nullable private final String reason;



  /**
   * Creates a new uninitialized enter lockdown mode task instance which should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  public LeaveLockdownModeTask()
  {
    reason = null;
  }



  /**
   * Creates a new leave lockdown mode task with the specified task ID.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   */
  public LeaveLockdownModeTask(@Nullable final String taskID)
  {
    this(taskID, null);
  }



  /**
   * Creates a new leave lockdown mode task with the specified task ID.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   * @param  reason  The user-specified reason for leaving lockdown mode. This
   *                 may be {@code null}.
   */
  public LeaveLockdownModeTask(@Nullable final String taskID,
                               @Nullable final String reason)
  {
    this(taskID, reason, null, null, null, null, null);
  }



  /**
   * Creates a new leave lockdown mode task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
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
  public LeaveLockdownModeTask(@Nullable final String taskID,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, null, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnCompletion, notifyOnError);
  }



  /**
   * Creates a new leave lockdown mode task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  reason                  The user-specified reason for leaving
   *                                 lockdown mode. This may be {@code null}.
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
  public LeaveLockdownModeTask(@Nullable final String taskID,
              @Nullable final String reason,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, reason, scheduledStartTime, dependencyIDs,
         failedDependencyAction, null, notifyOnCompletion, null,
         notifyOnError, null, null, null);
  }



  /**
   * Creates a new leave lockdown mode task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  reason                  The user-specified reason for leaving
   *                                 lockdown mode. This may be {@code null}.
   * @param  scheduledStartTime      The time that this task should start
   *                                 running.
   * @param  dependencyIDs           The list of task IDs that will be required
   *                                 to complete before this task will be
   *                                 eligible to start.
   * @param  failedDependencyAction  Indicates what action should be taken if
   *                                 any of the dependencies for this task do
   *                                 not complete successfully.
   * @param  notifyOnStart           The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 starts running.
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnSuccess         The list of e-mail addresses of individuals
   *                                 that should be notified if this task
   *                                 completes successfully.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   * @param  alertOnStart            Indicates whether the server should send an
   *                                 alert notification when this task starts.
   * @param  alertOnSuccess          Indicates whether the server should send an
   *                                 alert notification if this task completes
   *                                 successfully.
   * @param  alertOnError            Indicates whether the server should send an
   *                                 alert notification if this task fails to
   *                                 complete successfully.
   */
  public LeaveLockdownModeTask(@Nullable final String taskID,
              @Nullable final String reason,
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
    super(taskID, LEAVE_LOCKDOWN_MODE_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    this.reason = reason;
  }



  /**
   * Creates a new leave lockdown mode task from the provided entry.
   *
   * @param  entry  The entry to use to create this leave lockdown mode task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a leave
   *                         lockdown mode task entry.
   */
  public LeaveLockdownModeTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the "reason" string if it is present.
    reason = entry.getAttributeValue(ATTR_LEAVE_LOCKDOWN_REASON);
  }



  /**
   * Creates a new leave lockdown mode task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid leave lockdown mode task.
   */
  public LeaveLockdownModeTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(LEAVE_LOCKDOWN_MODE_TASK_CLASS, properties);

    String r = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
            properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_LEAVE_LOCKDOWN_REASON))
      {
        r = parseString(p, values, null);
        break;
      }
    }

    reason = r;
  }



  /**
   * Retrieves the user-specified reason why the server is leaving lockdown
   * mode.
   *
   * @return  The reason the server is leaving lockdown mode, or {@code null}
   *          if none was specified.
   */
  @Nullable()
  public String getReason()
  {
    return reason;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_LEAVE_LOCKDOWN_MODE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_LEAVE_LOCKDOWN_MODE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_LEAVE_LOCKDOWN_MODE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(1);
    if (reason != null)
    {
      attrs.add(new Attribute(ATTR_LEAVE_LOCKDOWN_REASON, reason));
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
    final List<TaskProperty> propList =
              Collections.singletonList(PROPERTY_LEAVE_LOCKDOWN_REASON);

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
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    if (reason != null)
    {
      props.put(PROPERTY_LEAVE_LOCKDOWN_REASON,
              Collections.<Object>singletonList(reason));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
