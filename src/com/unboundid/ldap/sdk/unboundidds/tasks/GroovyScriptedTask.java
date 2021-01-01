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
 * This class defines a Directory Server task that can be used to invoke a task
 * written as a Groovy script using the UnboundID Server SDK.
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
 *   <LI>The fully-qualified name of the Groovy class providing the logic for
 *       the scripted task.  This must be provided.</LI>
 *   <LI>A list of the arguments to use for the task.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GroovyScriptedTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the core
   * Groovy-scripted task.
   */
  @NotNull static final String GROOVY_SCRIPTED_TASK_CLASS =
       "com.unboundid.directory.sdk.extensions.GroovyScriptedTask";



  /**
   * The name of the attribute used to specify the fully-qualified name of the
   * Groovy class providing the logic for the scripted task.
   */
  @NotNull private static final String ATTR_GROOVY_SCRIPTED_TASK_CLASS =
       "ds-scripted-task-class";



  /**
   * The name of the attribute used to provide arguments to the script.
   */
  @NotNull private static final String ATTR_GROOVY_SCRIPTED_TASK_ARGUMENT =
       "ds-scripted-task-argument";



  /**
   * The name of the object class used in Groovy-scripted task entries.
   */
  @NotNull private static final String OC_GROOVY_SCRIPTED_TASK =
       "ds-groovy-scripted-task";



  /**
   * The task property that will be used for the task class.
   */
  @NotNull static final TaskProperty PROPERTY_TASK_CLASS =
     new TaskProperty(ATTR_GROOVY_SCRIPTED_TASK_CLASS,
          INFO_DISPLAY_NAME_GROOVY_SCRIPTED_TASK_CLASS.get(),
          INFO_DESCRIPTION_GROOVY_SCRIPTED_TASK_CLASS.get(), String.class, true,
          false, false);



  /**
   * The task property that will be used for the task arguments.
   */
  @NotNull static final TaskProperty PROPERTY_TASK_ARG =
     new TaskProperty(ATTR_GROOVY_SCRIPTED_TASK_ARGUMENT,
          INFO_DISPLAY_NAME_GROOVY_SCRIPTED_TASK_ARG.get(),
          INFO_DESCRIPTION_GROOVY_SCRIPTED_TASK_ARG.get(), String.class, false,
          true, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1354970323227263273L;



  // A list of the arguments for the task.
  @NotNull private final List<String> taskArguments;

  // The name of the Groovy class providing the logic for the scripted task.
  @NotNull private final String taskClassName;



  /**
   * Creates a new uninitialized Groovy-scripted task instance which should only
   * be used for obtaining general information about this task, including the
   * task name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public GroovyScriptedTask()
  {
    taskArguments = null;
    taskClassName = null;
  }



  /**
   * Creates a new Groovy-scripted task with the provided information.
   *
   * @param  taskID         The task ID to use for this task.  If it is
   *                        {@code null} then a UUID will be generated for use
   *                        as the task ID.
   * @param  taskClassName  The fully-qualified name of the Groovy class
   *                        providing the logic for the task.  It must not be
   *                        {@code null}.
   * @param  taskArguments  A list of the arguments for the task, in the form
   *                        name=value.  It may be {@code null} or empty if
   *                        there should not be any arguments.
   */
  public GroovyScriptedTask(@Nullable final String taskID,
                            @NotNull final String taskClassName,
                            @Nullable final List<String> taskArguments)
  {
    this(taskID, taskClassName, taskArguments, null, null, null, null, null);
  }



  /**
   * Creates a new Groovy-scripted task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  taskClassName           The fully-qualified name of the Groovy
   *                                 class providing the logic for the task.  It
   *                                 must not be {@code null}.
   * @param  taskArguments           A list of the arguments for the task, in
   *                                 the form name=value.  It may be
   *                                 {@code null} or empty if there should not
   *                                 be any arguments.
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
  public GroovyScriptedTask(@Nullable final String taskID,
              @NotNull final String taskClassName,
              @Nullable final List<String> taskArguments,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, taskClassName, taskArguments, scheduledStartTime,
         dependencyIDs, failedDependencyAction, null, notifyOnCompletion,
         null, notifyOnError, null, null, null);
  }



  /**
   * Creates a new Groovy-scripted task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  taskClassName           The fully-qualified name of the Groovy
   *                                 class providing the logic for the task.  It
   *                                 must not be {@code null}.
   * @param  taskArguments           A list of the arguments for the task, in
   *                                 the form name=value.  It may be
   *                                 {@code null} or empty if there should not
   *                                 be any arguments.
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
  public GroovyScriptedTask(@Nullable final String taskID,
              @NotNull final String taskClassName,
              @Nullable final List<String> taskArguments,
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
    super(taskID, GROOVY_SCRIPTED_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    Validator.ensureNotNull(taskClassName);

    this.taskClassName = taskClassName;

    if (taskArguments == null)
    {
      this.taskArguments = Collections.emptyList();
    }
    else
    {
      this.taskArguments = Collections.unmodifiableList(taskArguments);
    }
  }



  /**
   * Creates a new Groovy-scripted task from the provided entry.
   *
   * @param  entry  The entry to use to create this Groovy-scripted task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         Groovy-scripted task entry.
   */
  public GroovyScriptedTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the task class name.  It must be present.
    taskClassName = entry.getAttributeValue(ATTR_GROOVY_SCRIPTED_TASK_CLASS);
    if (taskClassName == null)
    {
      throw new TaskException(ERR_GROOVY_SCRIPTED_TASK_NO_CLASS.get(
           getTaskEntryDN()));
    }


    // Get the task arguments.  It may be absent.
    final String[] args =
         entry.getAttributeValues(ATTR_GROOVY_SCRIPTED_TASK_ARGUMENT);
    if ((args == null) || (args.length == 0))
    {
      taskArguments = Collections.emptyList();
    }
    else
    {
      taskArguments = Collections.unmodifiableList(Arrays.asList(args));
    }
  }



  /**
   * Creates a new Groovy-scripted task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid Groovy-scripted task.
   */
  public GroovyScriptedTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(GROOVY_SCRIPTED_TASK_CLASS, properties);

    String   className = null;
    String[] args      = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_GROOVY_SCRIPTED_TASK_CLASS))
      {
        className = parseString(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_GROOVY_SCRIPTED_TASK_ARGUMENT))
      {
        args = parseStrings(p, values, null);
      }
    }

    if (className == null)
    {
      throw new TaskException(ERR_GROOVY_SCRIPTED_TASK_NO_CLASS.get(
           getTaskEntryDN()));
    }

    taskClassName = className;

    if (args == null)
    {
      taskArguments = Collections.emptyList();
    }
    else
    {
      taskArguments = Collections.unmodifiableList(Arrays.asList(args));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_GROOVY_SCRIPTED_TASK.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_GROOVY_SCRIPTED_TASK.get();
  }



  /**
   * Retrieves the fully-qualified name of the Groovy class providing the logic
   * for the scripted task.
   *
   * @return  The fully-qualified name of the Groovy class providing the logic
   *          for the scripted task.
   */
  @NotNull()
  public String getGroovyScriptedTaskClassName()
  {
    return taskClassName;
  }



  /**
   * Retrieves a list of the arguments to provide to the Groovy-scripted task.
   *
   * @return  A list of the arguments to provide to the Groovy-scripted task, or
   *          an empty list if there are no arguments.
   */
  @NotNull()
  public List<String> getGroovyScriptedTaskArguments()
  {
    return taskArguments;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_GROOVY_SCRIPTED_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrList = new ArrayList<>(2);
    attrList.add(new Attribute(ATTR_GROOVY_SCRIPTED_TASK_CLASS, taskClassName));

    if (! taskArguments.isEmpty())
    {
      attrList.add(new Attribute(ATTR_GROOVY_SCRIPTED_TASK_ARGUMENT,
           taskArguments));
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
         PROPERTY_TASK_CLASS,
         PROPERTY_TASK_ARG));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));

    props.put(PROPERTY_TASK_CLASS,
         Collections.<Object>singletonList(taskClassName));

    props.put(PROPERTY_TASK_ARG,
         Collections.<Object>unmodifiableList(taskArguments));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
