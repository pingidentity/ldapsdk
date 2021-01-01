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



import java.util.Arrays;
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
 * This class defines a Directory Server task that can be used to shut down or
 * restart the server.
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
 *   <LI>A flag that indicates whether to shut down the server or to perform
 *       an in-core restart (in which the server shuts down and restarts itself
 *       within the same JVM).</LI>
 *   <LI>An optional message that can be used to provide a reason for the
 *       shutdown or restart.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ShutdownTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the shutdown
   * task.
   */
  @NotNull static final String SHUTDOWN_TASK_CLASS =
       "com.unboundid.directory.server.tasks.ShutdownTask";



  /**
   * The name of the attribute used to define a shutdown message.
   */
  @NotNull private static final String ATTR_SHUTDOWN_MESSAGE =
       "ds-task-shutdown-message";



  /**
   * The name of the attribute used to indicate whether to restart rather than
   * shut down the server.
   */
  @NotNull private static final String ATTR_RESTART_SERVER =
       "ds-task-restart-server";



  /**
   * The name of the object class used in shutdown task entries.
   */
  @NotNull private static final String OC_SHUTDOWN_TASK = "ds-task-shutdown";



  /**
   * The task property for the shutdown message.
   */
  @NotNull private static final TaskProperty PROPERTY_SHUTDOWN_MESSAGE =
       new TaskProperty(ATTR_SHUTDOWN_MESSAGE,
                        INFO_DISPLAY_NAME_SHUTDOWN_MESSAGE.get(),
                        INFO_DESCRIPTION_SHUTDOWN_MESSAGE.get(), String.class,
                        false, false, false);



  /**
   * The task property for the restart server flag.
   */
  @NotNull private static final TaskProperty PROPERTY_RESTART_SERVER =
       new TaskProperty(ATTR_RESTART_SERVER,
                        INFO_DISPLAY_NAME_RESTART_SERVER.get(),
                        INFO_DESCRIPTION_RESTART_SERVER.get(), Boolean.class,
                        false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5332685779844073667L;



  // Indicates whether to restart the server rather than shut it down.
  private final boolean restartServer;

  // A message that describes the reason for the shutdown.
  @Nullable private final String shutdownMessage;



  /**
   * Creates a new uninitialized shutdown task instance which should only be
   * used for obtaining general information about this task, including the task
   * name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public ShutdownTask()
  {
    shutdownMessage = null;
    restartServer   = false;
  }



  /**
   * Creates a new shutdown task with the provided information.
   *
   * @param  taskID           The task ID to use for this task.  If it is
   *                          {@code null} then a UUID will be generated for use
   *                          as the task ID.
   * @param  shutdownMessage  A message that describes the reason for the
   *                          shutdown.  It may be {@code null}.
   * @param  restartServer    Indicates whether to restart the server rather
   *                          than shut it down.
   */
  public ShutdownTask(@Nullable final String taskID,
                      @Nullable final String shutdownMessage,
                      final boolean restartServer)
  {
    this(taskID, shutdownMessage, restartServer, null, null, null, null, null);
  }



  /**
   * Creates a new shutdown task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  shutdownMessage         A message that describes the reason for the
   *                                 shutdown.  It may be {@code null}.
   * @param  restartServer           Indicates whether to restart the server
   *                                 rather than shut it down.
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
  public ShutdownTask(@Nullable final String taskID,
              @Nullable final String shutdownMessage,
              final boolean restartServer,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, shutdownMessage, restartServer, scheduledStartTime,
         dependencyIDs, failedDependencyAction, null, notifyOnCompletion,
         null, notifyOnError, null, null, null);
  }



  /**
   * Creates a new shutdown task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  shutdownMessage         A message that describes the reason for the
   *                                 shutdown.  It may be {@code null}.
   * @param  restartServer           Indicates whether to restart the server
   *                                 rather than shut it down.
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
  public ShutdownTask(@Nullable final String taskID,
              @Nullable final String shutdownMessage,
              final boolean restartServer,
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
    super(taskID, SHUTDOWN_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    this.shutdownMessage = shutdownMessage;
    this.restartServer   = restartServer;
  }



  /**
   * Creates a new shutdown task from the provided entry.
   *
   * @param  entry  The entry to use to create this shutdown task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         shutdown task entry.
   */
  public ShutdownTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the shutdown message.  It may be absent.
    shutdownMessage = entry.getAttributeValue(ATTR_SHUTDOWN_MESSAGE);


    // Get the restart server flag.  It may be absent.
    restartServer = parseBooleanValue(entry, ATTR_RESTART_SERVER, false);
  }



  /**
   * Creates a new shutdown task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid shutdown task.
   */
  public ShutdownTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(SHUTDOWN_TASK_CLASS, properties);

    boolean r = false;
    String  m = null;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_SHUTDOWN_MESSAGE))
      {
        m = parseString(p, values, m);
      }
      else if (attrName.equalsIgnoreCase(ATTR_RESTART_SERVER))
      {
        r = parseBoolean(p, values, r);
      }
    }

    shutdownMessage = m;
    restartServer   = r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_SHUTDOWN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_SHUTDOWN.get();
  }



  /**
   * Retrieves the shutdown message that may provide a reason for or additional
   * information about the shutdown or restart.
   *
   * @return  The shutdown message, or {@code null} if there is none.
   */
  @Nullable()
  public String getShutdownMessage()
  {
    return shutdownMessage;
  }



  /**
   * Indicates whether to attempt to restart the server rather than shut it
   * down.
   *
   * @return  {@code true} if the task should attempt to restart the server, or
   *          {@code false} if it should shut it down.
   */
  public boolean restartServer()
  {
    return restartServer;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_SHUTDOWN_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(2);

    if (shutdownMessage != null)
    {
      attrs.add(new Attribute(ATTR_SHUTDOWN_MESSAGE, shutdownMessage));
    }

    attrs.add(new Attribute(ATTR_RESTART_SERVER,
                            String.valueOf(restartServer)));

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
         PROPERTY_SHUTDOWN_MESSAGE,
         PROPERTY_RESTART_SERVER);

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

    if (shutdownMessage == null)
    {
      props.put(PROPERTY_SHUTDOWN_MESSAGE, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_SHUTDOWN_MESSAGE,
                Collections.<Object>singletonList(shutdownMessage));
    }

    props.put(PROPERTY_RESTART_SERVER,
              Collections.<Object>singletonList(restartServer));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
