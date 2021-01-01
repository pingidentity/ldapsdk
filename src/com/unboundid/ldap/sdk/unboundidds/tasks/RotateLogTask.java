/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
 * This class defines a Directory Server task that can be used to trigger the
 * rotation of one or more log files.
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
 *   <LI>The path to the log file to be rotated.  It may be either an absolute
 *       path or a path that is relative to the server root.  Multiple log files
 *       may be targeted by specifying multiple paths, and if no paths are given
 *       then the server will rotate all log files.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RotateLogTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the rotate log
   * task.
   */
  @NotNull static final String ROTATE_LOG_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RotateLogTask";



  /**
   * The name of the attribute used to specify the path to a log file to rotate.
   */
  @NotNull private static final String ATTR_PATH = "ds-task-rotate-log-path";



  /**
   * The name of the object class used in rotate log task entries.
   */
  @NotNull private static final String OC_ROTATE_LOG_TASK =
       "ds-task-rotate-log";



  /**
   * The task property that will be used for the log file path.
   */
  @NotNull private static final TaskProperty PROPERTY_PATH = new TaskProperty(
       ATTR_PATH, INFO_ROTATE_LOG_DISPLAY_NAME_PATH.get(),
       INFO_ROTATE_LOG_DESCRIPTION_PATH.get(), String.class, false, true,
       false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7737121245254808139L;



  // The paths of the log files to rotate.
  @NotNull private final List<String> paths;



  /**
   * Creates a new uninitialized rotate log task instance that should only be
   * used for obtaining general information about this task, including the task
   * name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public RotateLogTask()
  {
    paths = null;
  }



  /**
   * Creates a new rotate log task with the provided information.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   * @param  paths   The paths (on the server filesystem) of the log files to
   *                 rotate.  The paths may be either absolute or relative to
   *                 the server root.  This may be {@code null} or empty if the
   *                 server should rotate all appropriate log files.
   */
  public RotateLogTask(@Nullable final String taskID,
                       @Nullable final String... paths)
  {
    this(taskID, null, null, null, null, null, paths);
  }



  /**
   * Creates a new rotate log task with the provided information.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   * @param  paths   The paths (on the server filesystem) of the log files to
   *                 rotate.  The paths may be either absolute or relative to
   *                 the server root.  This may be {@code null} or empty if the
   *                 server should rotate all appropriate log files.
   */
  public RotateLogTask(@Nullable final String taskID,
                       @Nullable final Collection<String> paths)
  {
    this(taskID, null, null, null, null, null, paths);
  }



  /**
   * Creates a new rotate log task with the provided information.
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
   * @param  paths                   The paths (on the server filesystem) of the
   *                                 log files to rotate.  The paths may be
   *                                 either absolute or relative to the server
   *                                 root.  This may be {@code null} or empty if
   *                                 the server should rotate all appropriate
   *                                 log files.
   */
  public RotateLogTask(@Nullable final String taskID,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError,
              @Nullable final String... paths)
  {
    this(taskID, scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnCompletion, notifyOnError, StaticUtils.toList(paths));
  }



  /**
   * Creates a new rotate log task with the provided information.
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
   * @param  paths                   The paths (on the server filesystem) of the
   *                                 log files to rotate.  The paths may be
   *                                 either absolute or relative to the server
   *                                 root.  This may be {@code null} or empty if
   *                                 the server should rotate all appropriate
   *                                 log files.
   */
  public RotateLogTask(@Nullable final String taskID,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError,
              @Nullable final Collection<String> paths)
  {
    this(taskID, scheduledStartTime, dependencyIDs, failedDependencyAction,
         null, notifyOnCompletion, null, notifyOnError, null, null, null,
         paths);
  }



  /**
   * Creates a new rotate log task with the provided information.
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
   * @param  paths                   The paths (on the server filesystem) of the
   *                                 log files to rotate.  The paths may be
   *                                 either absolute or relative to the server
   *                                 root.  This may be {@code null} or empty if
   *                                 the server should rotate all appropriate
   *                                 log files.
   */
  public RotateLogTask(@Nullable final String taskID,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnStart,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnSuccess,
              @Nullable final List<String> notifyOnError,
              @Nullable final Boolean alertOnStart,
              @Nullable final Boolean alertOnSuccess,
              @Nullable final Boolean alertOnError,
              @Nullable final Collection<String> paths)
  {
    super(taskID, ROTATE_LOG_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    if (paths == null)
    {
      this.paths = Collections.emptyList();
    }
    else
    {
      this.paths = Collections.unmodifiableList(new ArrayList<>(paths));
    }
  }



  /**
   * Creates a new rotate log task from the provided entry.
   *
   * @param  entry  The entry to use to create this rotate log task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a rotate
   *                         log task entry.
   */
  public RotateLogTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the log file paths, if present.
    final String[] pathValues = entry.getAttributeValues(ATTR_PATH);
    if (pathValues == null)
    {
      paths = Collections.emptyList();
    }
    else
    {
      paths = Collections.unmodifiableList(new ArrayList<>(
           Arrays.asList(pathValues)));
    }
  }



  /**
   * Creates a new rotate log task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid rotate log task.
   */
  public RotateLogTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(ROTATE_LOG_TASK_CLASS, properties);

    String[] pathArray = StaticUtils.NO_STRINGS;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_PATH))
      {
        pathArray = parseStrings(p, values, pathArray);
      }
    }

    paths = Collections.unmodifiableList(Arrays.asList(pathArray));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_ROTATE_LOG.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_ROTATE_LOG.get();
  }



  /**
   * Retrieves the paths of the log files to rotate.  The paths may be
   * absolute or relative to the server root.
   *
   * @return  The paths of the log files to rotate, or an empty list if no
   *          paths were specified and the server should rotate the log files
   *          for all applicable loggers.
   */
  @NotNull()
  public List<String> getPaths()
  {
    return paths;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_ROTATE_LOG_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    if (paths.isEmpty())
    {
      return Collections.emptyList();
    }
    else
    {
      return Collections.singletonList(new Attribute(ATTR_PATH, paths));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.singletonList(PROPERTY_PATH);
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


    if (! paths.isEmpty())
    {
      props.put(PROPERTY_PATH, Collections.<Object>unmodifiableList(paths));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
