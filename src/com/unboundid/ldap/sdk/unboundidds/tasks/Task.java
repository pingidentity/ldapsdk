/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class defines a data structure for holding information about scheduled
 * tasks as used by the Ping Identity, UnboundID, or Alcatel-Lucent 8661
 * Directory Server.  Subclasses be used to provide additional functionality
 * when dealing with certain types of tasks.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * All types of tasks can include the following information:
 * <UL>
 *   <LI>Task ID -- Uniquely identifies the task in the server.  It may be
 *       omitted when scheduling a new task in order to have a task ID generated
 *       for the task.</LI>
 *   <LI>Task Class Name -- The fully-qualified name of the {@code Task}
 *       subclass that provides the logic for the task.  This does not need to
 *       be provided when creating a new task from one of the task-specific
 *       subclasses.</LI>
 *   <LI>Task State -- The current state of the task.  See the {@link TaskState}
 *       enum for information about the possible states that a task may
 *       have.</LI>
 *   <LI>Scheduled Start Time -- The earliest time that the task should be
 *       eligible to start.  It may be omitted when scheduling a new task in
 *       order to use the current time.</LI>
 *   <LI>Actual Start Time -- The time that server started processing the
 *       task.</LI>
 *   <LI>Actual Start Time -- The time that server completed processing for the
 *       task.</LI>
 *   <LI>Dependency IDs -- A list of task IDs for tasks that must complete
 *       before this task may be considered eligible to start.</LI>
 *   <LI>Failed Dependency Action -- Specifies how the server should treat this
 *       task if any of the tasks on which it depends failed.  See the
 *       {@link FailedDependencyAction} enum for the failed dependency action
 *       values that may be used.</LI>
 *   <LI>Notify on Completion -- A list of e-mail addresses for users that
 *       should be notified when the task completes, regardless of whether it
 *       was successful.</LI>
 *   <LI>Notify On Error -- A list of e-mail addresses for users that should be
 *       notified if the task fails.</LI>
 *   <LI>Log Messages -- A list of the messages logged by the task while it was
 *       running.</LI>
 * </UL>
 * Each of these elements can be retrieving using specific methods within this
 * class (e.g., the {@link Task#getTaskID} method can be used to retrieve the
 * task ID), but task properties (including those specific to the particular
 * type to task) may also be accessed using a generic API.  For example, the
 * {@link Task#getTaskPropertyValues} method retrieves a map that correlates the
 * {@link TaskProperty} objects for the task with the values that have been set
 * for those properties.  See the documentation for the {@link TaskManager}
 * class for an example that demonstrates accessing task information using the
 * generic API.
 * <BR><BR>
 * Also note that it is possible to create new tasks using information obtained
 * from the generic API, but that is done on a per-class basis.  For example, in
 * order to create a new {@link BackupTask} instance using the generic API, you
 * would use the {@link BackupTask#BackupTask(Map)} constructor, in which the
 * provided map contains a mapping between the properties and their values for
 * that task.  The {@link Task#getTaskSpecificProperties} method may be used to
 * retrieve a list of the task-specific properties that may be provided when
 * scheduling a task, and the {@link Task#getCommonTaskProperties} method may be
 * used to retrieve a list of properties that can be provided when scheduling
 * any type of task.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class Task
       implements Serializable
{
  /**
   * The name of the attribute used to hold the actual start time for scheduled
   * tasks.
   */
  static final String ATTR_ACTUAL_START_TIME = "ds-task-actual-start-time";



  /**
   * The name of the attribute used to hold the completion time for scheduled
   * tasks.
   */
  static final String ATTR_COMPLETION_TIME = "ds-task-completion-time";



  /**
   * The name of the attribute used to hold the task IDs for tasks on which a
   * scheduled task is dependent.
   */
  static final String ATTR_DEPENDENCY_ID = "ds-task-dependency-id";



  /**
   * The name of the attribute used to indicate what action to take if one of
   * the dependencies for a task failed to complete successfully.
   */
  static final String ATTR_FAILED_DEPENDENCY_ACTION =
       "ds-task-failed-dependency-action";



  /**
   * The name of the attribute used to hold the log messages for scheduled
   * tasks.
   */
  static final String ATTR_LOG_MESSAGE = "ds-task-log-message";



  /**
   * The name of the attribute used to hold the e-mail addresses of the users
   * that should be notified whenever a scheduled task completes, regardless of
   * success or failure.
   */
  static final String ATTR_NOTIFY_ON_COMPLETION =
       "ds-task-notify-on-completion";



  /**
   * The name of the attribute used to hold the e-mail addresses of the users
   * that should be notified if a scheduled task fails to complete successfully.
   */
  static final String ATTR_NOTIFY_ON_ERROR = "ds-task-notify-on-error";



  /**
   * The name of the attribute used to hold the scheduled start time for
   * scheduled tasks.
   */
  static final String ATTR_SCHEDULED_START_TIME =
       "ds-task-scheduled-start-time";



  /**
   * The name of the attribute used to hold the name of the class that provides
   * the logic for scheduled tasks.
   */
  static final String ATTR_TASK_CLASS = "ds-task-class-name";



  /**
   * The name of the attribute used to hold the task ID for scheduled tasks.
   */
  static final String ATTR_TASK_ID = "ds-task-id";



  /**
   * The name of the attribute used to hold the current state for scheduled
   * tasks.
   */
  static final String ATTR_TASK_STATE = "ds-task-state";



  /**
   * The name of the base object class for scheduled tasks.
   */
  static final String OC_TASK = "ds-task";



  /**
   * The DN of the entry below which scheduled tasks reside.
   */
  static final String SCHEDULED_TASKS_BASE_DN =
       "cn=Scheduled Tasks,cn=tasks";



  /**
   * The task property that will be used for the task ID.
   */
  static final TaskProperty PROPERTY_TASK_ID =
       new TaskProperty(ATTR_TASK_ID, INFO_DISPLAY_NAME_TASK_ID.get(),
                        INFO_DESCRIPTION_TASK_ID.get(), String.class, false,
                        false, true);



  /**
   * The task property that will be used for the scheduled start time.
   */
  static final TaskProperty PROPERTY_SCHEDULED_START_TIME =
       new TaskProperty(ATTR_SCHEDULED_START_TIME,
                        INFO_DISPLAY_NAME_SCHEDULED_START_TIME.get(),
                        INFO_DESCRIPTION_SCHEDULED_START_TIME.get(), Date.class,
                        false, false, true);



  /**
   * The task property that will be used for the set of dependency IDs.
   */
  static final TaskProperty PROPERTY_DEPENDENCY_ID =
       new TaskProperty(ATTR_DEPENDENCY_ID,
                        INFO_DISPLAY_NAME_DEPENDENCY_ID.get(),
                        INFO_DESCRIPTION_DEPENDENCY_ID.get(), String.class,
                        false, true, true);



  /**
   * The task property that will be used for the failed dependency action.
   */
  static final TaskProperty PROPERTY_FAILED_DEPENDENCY_ACTION =
       new TaskProperty(ATTR_FAILED_DEPENDENCY_ACTION,
                        INFO_DISPLAY_NAME_FAILED_DEPENDENCY_ACTION.get(),
                        INFO_DESCRIPTION_FAILED_DEPENDENCY_ACTION.get(),
                        String.class, false, false, true,
                        new String[]
                        {
                          FailedDependencyAction.CANCEL.getName(),
                          FailedDependencyAction.DISABLE.getName(),
                          FailedDependencyAction.PROCESS.getName()
                        });



  /**
   * The task property that will be used for the notify on completion addresses.
   */
  static final TaskProperty PROPERTY_NOTIFY_ON_COMPLETION =
       new TaskProperty(ATTR_NOTIFY_ON_COMPLETION,
                        INFO_DISPLAY_NAME_NOTIFY_ON_COMPLETION.get(),
                        INFO_DESCRIPTION_NOTIFY_ON_COMPLETION.get(),
                        String.class, false, true, true);



  /**
   * The task property that will be used for the notify on error addresses.
   */
  static final TaskProperty PROPERTY_NOTIFY_ON_ERROR =
       new TaskProperty(ATTR_NOTIFY_ON_ERROR,
                        INFO_DISPLAY_NAME_NOTIFY_ON_ERROR.get(),
                        INFO_DESCRIPTION_NOTIFY_ON_ERROR.get(),
                        String.class, false, true, true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3521189553470479032L;



  // The time that this task actually started.
  private final Date actualStartTime;

  // The time that this task completed.
  private final Date completionTime;

  // The time that this task was scheduled to start.
  private final Date scheduledStartTime;

  // The entry from which this task was decoded.
  private final Entry taskEntry;

  // The failed dependency action for this task.
  private final FailedDependencyAction failedDependencyAction;

  // The set of task IDs of the tasks on which this task is dependent.
  private final List<String> dependencyIDs;

  // The set of log messages for this task.
  private final List<String> logMessages;

  // The set of e-mail addresses of users that should be notified when the task
  // processing is complete.
  private final List<String> notifyOnCompletion;

  // The set of e-mail addresses of users that should be notified if task
  // processing completes with an error.
  private final List<String> notifyOnError;

  // The fully-qualified name of the task class.
  private final String taskClassName;

  // The DN of the entry for this task.
  private final String taskEntryDN;

  // The task ID for this task.
  private final String taskID;

  // The current state for this task.
  private final TaskState taskState;



  /**
   * Creates a new uninitialized task instance which should only be used for
   * obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  protected Task()
  {
    actualStartTime        = null;
    completionTime         = null;
    scheduledStartTime     = null;
    taskEntry              = null;
    failedDependencyAction = null;
    dependencyIDs          = null;
    logMessages            = null;
    notifyOnCompletion     = null;
    notifyOnError          = null;
    taskClassName          = null;
    taskEntryDN            = null;
    taskID                 = null;
    taskState              = null;
  }



  /**
   * Creates a new unscheduled task with the specified task ID and class name.
   *
   * @param  taskID         The task ID to use for this task.  If it is
   *                        {@code null} then a UUID will be generated for use
   *                        as the task ID.
   * @param  taskClassName  The fully-qualified name of the Java class that
   *                        provides the logic for the task.  It must not be
   *                        {@code null}.
   */
  public Task(final String taskID, final String taskClassName)
  {
    this(taskID, taskClassName, null, null, null, null, null);
  }



  /**
   * Creates a new unscheduled task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.
   * @param  taskClassName           The fully-qualified name of the Java class
   *                                 that provides the logic for the task.  It
   *                                 must not be {@code null}.
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
  public Task(final String taskID, final String taskClassName,
              final Date scheduledStartTime, final List<String> dependencyIDs,
              final FailedDependencyAction failedDependencyAction,
              final List<String> notifyOnCompletion,
              final List<String> notifyOnError)
  {
    ensureNotNull(taskClassName);

    this.taskClassName          = taskClassName;
    this.scheduledStartTime     = scheduledStartTime;
    this.failedDependencyAction = failedDependencyAction;

    if (taskID == null)
    {
      this.taskID = UUID.randomUUID().toString();
    }
    else
    {
      this.taskID = taskID;
    }

    if (dependencyIDs == null)
    {
      this.dependencyIDs = Collections.emptyList();
    }
    else
    {
      this.dependencyIDs = Collections.unmodifiableList(dependencyIDs);
    }

    if (notifyOnCompletion == null)
    {
      this.notifyOnCompletion = Collections.emptyList();
    }
    else
    {
      this.notifyOnCompletion =
           Collections.unmodifiableList(notifyOnCompletion);
    }

    if (notifyOnError == null)
    {
      this.notifyOnError = Collections.emptyList();
    }
    else
    {
      this.notifyOnError = Collections.unmodifiableList(notifyOnError);
    }

    taskEntry       = null;
    taskEntryDN     = ATTR_TASK_ID + '=' + this.taskID + ',' +
                      SCHEDULED_TASKS_BASE_DN;
    actualStartTime = null;
    completionTime  = null;
    logMessages     = Collections.emptyList();
    taskState       = TaskState.UNSCHEDULED;
  }



  /**
   * Creates a new task from the provided entry.
   *
   * @param  entry  The entry to use to create this task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         scheduled task.
   */
  public Task(final Entry entry)
         throws TaskException
  {
    taskEntry   = entry;
    taskEntryDN = entry.getDN();

    // Ensure that the task entry has the appropriate object class for a
    // scheduled task.
    if (! entry.hasObjectClass(OC_TASK))
    {
      throw new TaskException(ERR_TASK_MISSING_OC.get(taskEntryDN));
    }


    // Get the task ID.  It must be present.
    taskID = entry.getAttributeValue(ATTR_TASK_ID);
    if (taskID == null)
    {
      throw new TaskException(ERR_TASK_NO_ID.get(taskEntryDN));
    }


    // Get the task class name.  It must be present.
    taskClassName = entry.getAttributeValue(ATTR_TASK_CLASS);
    if (taskClassName == null)
    {
      throw new TaskException(ERR_TASK_NO_CLASS.get(taskEntryDN));
    }


    // Get the task state.  If it is not present, then assume "unscheduled".
    final String stateStr = entry.getAttributeValue(ATTR_TASK_STATE);
    if (stateStr == null)
    {
      taskState = TaskState.UNSCHEDULED;
    }
    else
    {
      taskState = TaskState.forName(stateStr);
      if (taskState == null)
      {
        throw new TaskException(ERR_TASK_INVALID_STATE.get(taskEntryDN,
                                                           stateStr));
      }
    }


    // Get the scheduled start time.  It may be absent.
    String timestamp = entry.getAttributeValue(ATTR_SCHEDULED_START_TIME);
    if (timestamp == null)
    {
      scheduledStartTime = null;
    }
    else
    {
      try
      {
        scheduledStartTime = decodeGeneralizedTime(timestamp);
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new TaskException(ERR_TASK_CANNOT_PARSE_SCHEDULED_START_TIME.get(
                                     taskEntryDN, timestamp, pe.getMessage()),
                                pe);
      }
    }


    // Get the actual start time.  It may be absent.
    timestamp = entry.getAttributeValue(ATTR_ACTUAL_START_TIME);
    if (timestamp == null)
    {
      actualStartTime = null;
    }
    else
    {
      try
      {
        actualStartTime = decodeGeneralizedTime(timestamp);
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new TaskException(ERR_TASK_CANNOT_PARSE_ACTUAL_START_TIME.get(
                                     taskEntryDN, timestamp, pe.getMessage()),
                                pe);
      }
    }


    // Get the completion start time.  It may be absent.
    timestamp = entry.getAttributeValue(ATTR_COMPLETION_TIME);
    if (timestamp == null)
    {
      completionTime = null;
    }
    else
    {
      try
      {
        completionTime = decodeGeneralizedTime(timestamp);
      }
      catch (final ParseException pe)
      {
        debugException(pe);
        throw new TaskException(ERR_TASK_CANNOT_PARSE_COMPLETION_TIME.get(
                                     taskEntryDN, timestamp, pe.getMessage()),
                                pe);
      }
    }


    // Get the failed dependency action for this task.  It may be absent.
    final String name = entry.getAttributeValue(ATTR_FAILED_DEPENDENCY_ACTION);
    if (name == null)
    {
      failedDependencyAction = null;
    }
    else
    {
      failedDependencyAction = FailedDependencyAction.forName(name);
    }


    // Get the dependent task IDs for this task.  It may be absent.
    dependencyIDs = parseStringList(entry, ATTR_DEPENDENCY_ID);


    // Get the log messages for this task.  It may be absent.
    logMessages = parseStringList(entry, ATTR_LOG_MESSAGE);


    // Get the notify on completion addresses for this task.  It may be absent.
    notifyOnCompletion = parseStringList(entry, ATTR_NOTIFY_ON_COMPLETION);


    // Get the notify on error addresses for this task.  It may be absent.
    notifyOnError = parseStringList(entry, ATTR_NOTIFY_ON_ERROR);
  }



  /**
   * Creates a new task from the provided set of task properties.
   *
   * @param  taskClassName  The fully-qualified name of the Java class that
   *                        provides the logic for the task.  It must not be
   *                        {@code null}.
   * @param  properties     The set of task properties and their corresponding
   *                        values to use for the task.  It must not be
   *                        {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid scheduled task.
   */
  public Task(final String taskClassName,
              final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    ensureNotNull(taskClassName, properties);

    this.taskClassName = taskClassName;

    String                 idStr  = UUID.randomUUID().toString();
    Date                   sst    = null;
    String[]               depIDs = NO_STRINGS;
    FailedDependencyAction fda    = FailedDependencyAction.CANCEL;
    String[]               noc    = NO_STRINGS;
    String[]               noe    = NO_STRINGS;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p        = entry.getKey();
      final String       attrName = p.getAttributeName();
      final List<Object> values   = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_TASK_ID))
      {
        idStr = parseString(p, values, idStr);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SCHEDULED_START_TIME))
      {
        sst = parseDate(p, values, sst);
      }
      else if (attrName.equalsIgnoreCase(ATTR_DEPENDENCY_ID))
      {
        depIDs = parseStrings(p, values, depIDs);
      }
      else if (attrName.equalsIgnoreCase(ATTR_FAILED_DEPENDENCY_ACTION))
      {
        fda = FailedDependencyAction.forName(
                   parseString(p, values, fda.getName()));
      }
      else if (attrName.equalsIgnoreCase(ATTR_NOTIFY_ON_COMPLETION))
      {
        noc = parseStrings(p, values, noc);
      }
      else if (attrName.equalsIgnoreCase(ATTR_NOTIFY_ON_ERROR))
      {
        noe = parseStrings(p, values, noe);
      }
    }

    taskID = idStr;
    scheduledStartTime = sst;
    dependencyIDs = Collections.unmodifiableList(Arrays.asList(depIDs));
    failedDependencyAction = fda;
    notifyOnCompletion = Collections.unmodifiableList(Arrays.asList(noc));
    notifyOnError = Collections.unmodifiableList(Arrays.asList(noe));
    taskEntry = null;
    taskEntryDN = ATTR_TASK_ID + '=' + taskID + ',' + SCHEDULED_TASKS_BASE_DN;
    actualStartTime = null;
    completionTime = null;
    logMessages = Collections.emptyList();
    taskState = TaskState.UNSCHEDULED;
  }



  /**
   * Retrieves a list containing instances of the available task types.  The
   * provided task instances will may only be used for obtaining general
   * information about the task (e.g., name, description, and supported
   * properties).
   *
   * @return  A list containing instances of the available task types.
   */
  public static List<Task> getAvailableTaskTypes()
  {
    final List<Task> taskList = Arrays.asList(
         new AddSchemaFileTask(),
         new AlertTask(),
         new AuditDataSecurityTask(),
         new BackupTask(),
         new DisconnectClientTask(),
         new DumpDBDetailsTask(),
         new EnterLockdownModeTask(),
         new ExportTask(),
         new GroovyScriptedTask(),
         new ImportTask(),
         new LeaveLockdownModeTask(),
         new RebuildTask(),
         new ReEncodeEntriesTask(),
         new RefreshEncryptionSettingsTask(),
         new ReloadGlobalIndexTask(),
         new RestoreTask(),
         new RotateLogTask(),
         new SearchTask(),
         new ShutdownTask(),
         new SynchronizeEncryptionSettingsTask(),
         new ThirdPartyTask());

    return Collections.unmodifiableList(taskList);
  }



  /**
   * Retrieves a human-readable name for this task.
   *
   * @return  A human-readable name for this task.
   */
  public String getTaskName()
  {
    return INFO_TASK_NAME_GENERIC.get();
  }



  /**
   * Retrieves a human-readable description for this task.
   *
   * @return  A human-readable description for this task.
   */
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_GENERIC.get();
  }



  /**
   * Retrieves the entry from which this task was decoded, if available.  Note
   * that although the entry is not immutable, changes made to it will not be
   * reflected in this task.
   *
   * @return  The entry from which this task was decoded, or {@code null} if
   *          this task was not created from an existing entry.
   */
  protected final Entry getTaskEntry()
  {
    return taskEntry;
  }



  /**
   * Retrieves the DN of the entry in which this scheduled task is defined.
   *
   * @return  The DN of the entry in which this scheduled task is defined.
   */
  public final String getTaskEntryDN()
  {
    return taskEntryDN;
  }



  /**
   * Retrieves the task ID for this task.
   *
   * @return  The task ID for this task.
   */
  public final String getTaskID()
  {
    return taskID;
  }



  /**
   * Retrieves the fully-qualified name of the Java class that provides the
   * logic for this class.
   *
   * @return  The fully-qualified name of the Java class that provides the logic
   *          for this task.
   */
  public final String getTaskClassName()
  {
    return taskClassName;
  }



  /**
   * Retrieves the current state for this task.
   *
   * @return  The current state for this task.
   */
  public final TaskState getState()
  {
    return taskState;
  }



  /**
   * Indicates whether this task is currently pending execution.
   *
   * @return  {@code true} if this task is currently pending execution, or
   *          {@code false} if not.
   */
  public final boolean isPending()
  {
    return taskState.isPending();
  }



  /**
   * Indicates whether this task is currently running.
   *
   * @return  {@code true} if this task is currently running, or {@code false}
   *          if not.
   */
  public final boolean isRunning()
  {
    return taskState.isRunning();
  }



  /**
   * Indicates whether this task has completed execution.
   *
   * @return  {@code true} if this task has completed execution, or
   *          {@code false} if not.
   */
  public final boolean isCompleted()
  {
    return taskState.isCompleted();
  }



  /**
   * Retrieves the time that this task is/was scheduled to start running.
   *
   * @return  The time that this task is/was scheduled to start running, or
   *          {@code null} if that is not available and therefore the task
   *          should start running as soon as all dependencies have been met.
   */
  public final Date getScheduledStartTime()
  {
    return scheduledStartTime;
  }



  /**
   * Retrieves the time that this task actually started running.
   *
   * @return  The time that this task actually started running, or {@code null}
   *          if that is not available (e.g., because the task has not yet
   *          started).
   */
  public final Date getActualStartTime()
  {
    return actualStartTime;
  }



  /**
   * Retrieves the time that this task completed.
   *
   * @return  The time that this task completed, or {@code null} if it has not
   *          yet completed.
   */
  public final Date getCompletionTime()
  {
    return completionTime;
  }



  /**
   * Retrieves a list of the task IDs for tasks that must complete before this
   * task will be eligible to start.
   *
   * @return  A list of the task IDs for tasks that must complete before this
   *          task will be eligible to start, or an empty list if this task does
   *          not have any dependencies.
   */
  public final List<String> getDependencyIDs()
  {
    return dependencyIDs;
  }



  /**
   * Retrieves the failed dependency action for this task, which indicates the
   * behavior that it should exhibit if any of its dependencies encounter a
   * failure.
   *
   * @return  The failed dependency action for this task, or {@code null} if it
   *          is not available.
   */
  public final FailedDependencyAction getFailedDependencyAction()
  {
    return failedDependencyAction;
  }



  /**
   * Retrieves the log messages for this task.  Note that if the task has
   * generated a very large number of log messages, then only a portion of the
   * most recent messages may be available.
   *
   * @return  The log messages for this task, or an empty list if this task does
   *          not have any log messages.
   */
  public final List<String> getLogMessages()
  {
    return logMessages;
  }



  /**
   * Retrieves a list of the e-mail addresses of the individuals that should be
   * notified whenever this task completes processing, regardless of whether it
   * was successful.
   *
   * @return  A list of the e-mail addresses of the individuals that should be
   *          notified whenever this task completes processing, or an empty list
   *          if there are none.
   */
  public final List<String> getNotifyOnCompletionAddresses()
  {
    return notifyOnCompletion;
  }



  /**
   * Retrieves a list of the e-mail addresses of the individuals that should be
   * notified if this task stops processing prematurely due to an error or
   * other external action (e.g., server shutdown or administrative cancel).
   *
   * @return  A list of the e-mail addresses of the individuals that should be
   *          notified if this task stops processing prematurely, or an empty
   *          list if there are none.
   */
  public final List<String> getNotifyOnErrorAddresses()
  {
    return notifyOnError;
  }



  /**
   * Creates an entry that may be added to the Directory Server to create a new
   * instance of this task.
   *
   * @return  An entry that may be added to the Directory Server to create a new
   *          instance of this task.
   */
  public final Entry createTaskEntry()
  {
    final ArrayList<Attribute> attributes = new ArrayList<Attribute>();

    final ArrayList<String> ocValues = new ArrayList<String>(5);
    ocValues.add("top");
    ocValues.add(OC_TASK);
    ocValues.addAll(getAdditionalObjectClasses());
    attributes.add(new Attribute("objectClass", ocValues));

    attributes.add(new Attribute(ATTR_TASK_ID, taskID));

    attributes.add(new Attribute(ATTR_TASK_CLASS, taskClassName));

    if (scheduledStartTime != null)
    {
      attributes.add(new Attribute(ATTR_SCHEDULED_START_TIME,
                                   encodeGeneralizedTime(scheduledStartTime)));
    }

    if (! dependencyIDs.isEmpty())
    {
      attributes.add(new Attribute(ATTR_DEPENDENCY_ID, dependencyIDs));
    }

    if (failedDependencyAction != null)
    {
      attributes.add(new Attribute(ATTR_FAILED_DEPENDENCY_ACTION,
                                   failedDependencyAction.getName()));
    }

    if (! notifyOnCompletion.isEmpty())
    {
      attributes.add(new Attribute(ATTR_NOTIFY_ON_COMPLETION,
                                   notifyOnCompletion));
    }

    if (! notifyOnError.isEmpty())
    {
      attributes.add(new Attribute(ATTR_NOTIFY_ON_ERROR, notifyOnError));
    }

    attributes.addAll(getAdditionalAttributes());

    return new Entry(taskEntryDN, attributes);
  }



  /**
   * Parses the value of the specified attribute as a {@code boolean} value, or
   * throws an exception if the value cannot be decoded as a boolean.
   *
   * @param  taskEntry      The entry containing the attribute to be parsed.
   * @param  attributeName  The name of the attribute from which the value was
   *                        taken.
   * @param  defaultValue   The default value to use if the provided value
   *                        string is {@code null}.
   *
   * @return  {@code true} if the value string represents a boolean value of
   *          {@code true}, {@code false} if the value string represents a
   *          boolean value of {@code false}, or the default value if the value
   *          string is {@code null}.
   *
   * @throws  TaskException  If the provided value string cannot be parsed as a
   *                         {@code boolean} value.
   */
  protected static boolean parseBooleanValue(final Entry taskEntry,
                                             final String attributeName,
                                             final boolean defaultValue)
            throws TaskException
  {
    final String valueString = taskEntry.getAttributeValue(attributeName);
    if (valueString == null)
    {
      return defaultValue;
    }
    else if (valueString.equalsIgnoreCase("true"))
    {
      return true;
    }
    else if (valueString.equalsIgnoreCase("false"))
    {
      return false;
    }
    else
    {
      throw new TaskException(ERR_TASK_CANNOT_PARSE_BOOLEAN.get(
                                   taskEntry.getDN(), valueString,
                                   attributeName));
    }
  }



  /**
   * Parses the values of the specified attribute as a list of strings.
   *
   * @param  taskEntry      The entry containing the attribute to be parsed.
   * @param  attributeName  The name of the attribute from which the value was
   *                        taken.
   *
   * @return  A list of strings containing the values of the specified
   *          attribute, or an empty list if the specified attribute does not
   *          exist in the target entry.  The returned list will be
   *          unmodifiable.
   */
  protected static List<String> parseStringList(final Entry taskEntry,
                                                final String attributeName)
  {
    final String[] valueStrings = taskEntry.getAttributeValues(attributeName);
    if (valueStrings == null)
    {
      return Collections.emptyList();
    }
    else
    {
      return Collections.unmodifiableList(Arrays.asList(valueStrings));
    }
  }



  /**
   * Parses the provided set of values for the associated task property as a
   * {@code Boolean}.
   *
   * @param  p             The task property with which the values are
   *                       associated.
   * @param  values        The provided values for the task property.
   * @param  defaultValue  The default value to use if the provided object array
   *                       is empty.
   *
   * @return  The parsed {@code Boolean} value.
   *
   * @throws  TaskException  If there is a problem with the provided values.
   */
  protected static Boolean parseBoolean(final TaskProperty p,
                                        final List<Object> values,
                                        final Boolean defaultValue)
            throws TaskException
  {
    // Check to see if any values were provided.  If not, then it may or may not
    // be a problem.
    if (values.isEmpty())
    {
      if (p.isRequired())
      {
        throw new TaskException(ERR_TASK_REQUIRED_PROPERTY_WITHOUT_VALUES.get(
                                     p.getDisplayName()));
      }
      else
      {
        return defaultValue;
      }
    }

    // If there were multiple values, then that's always an error.
    if (values.size() > 1)
    {
      throw new TaskException(ERR_TASK_PROPERTY_NOT_MULTIVALUED.get(
                                   p.getDisplayName()));
    }

    // Make sure that the value can be interpreted as a Boolean.
    final Boolean booleanValue;
    final Object o = values.get(0);
    if (o instanceof Boolean)
    {
      booleanValue = (Boolean) o;
    }
    else if (o instanceof String)
    {
      final String valueStr = (String) o;
      if (valueStr.equalsIgnoreCase("true"))
      {
        booleanValue = Boolean.TRUE;
      }
      else if (valueStr.equalsIgnoreCase("false"))
      {
        booleanValue = Boolean.FALSE;
      }
      else
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_BOOLEAN.get(
                                     p.getDisplayName()));
      }
    }
    else
    {
      throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_BOOLEAN.get(
                                   p.getDisplayName()));
    }

    return booleanValue;
  }



  /**
   * Parses the provided set of values for the associated task property as a
   * {@code Date}.
   *
   * @param  p             The task property with which the values are
   *                       associated.
   * @param  values        The provided values for the task property.
   * @param  defaultValue  The default value to use if the provided object array
   *                       is empty.
   *
   * @return  The parsed {@code Date} value.
   *
   * @throws  TaskException  If there is a problem with the provided values.
   */
  protected static Date parseDate(final TaskProperty p,
                                  final List<Object> values,
                                  final Date defaultValue)
            throws TaskException
  {
    // Check to see if any values were provided.  If not, then it may or may not
    // be a problem.
    if (values.isEmpty())
    {
      if (p.isRequired())
      {
        throw new TaskException(ERR_TASK_REQUIRED_PROPERTY_WITHOUT_VALUES.get(
                                     p.getDisplayName()));
      }
      else
      {
        return defaultValue;
      }
    }

    // If there were multiple values, then that's always an error.
    if (values.size() > 1)
    {
      throw new TaskException(ERR_TASK_PROPERTY_NOT_MULTIVALUED.get(
                                   p.getDisplayName()));
    }

    // Make sure that the value can be interpreted as a Date.
    final Date dateValue;
    final Object o = values.get(0);
    if (o instanceof Date)
    {
      dateValue = (Date) o;
    }
    else if (o instanceof String)
    {
      try
      {
        dateValue = decodeGeneralizedTime((String) o);
      }
      catch (final ParseException pe)
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_DATE.get(
                                     p.getDisplayName()), pe);
      }
    }
    else
    {
      throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_DATE.get(
                                   p.getDisplayName()));
    }

    // If the task property has a set of allowed values, then make sure that the
    // provided value is acceptable.
    final Object[] allowedValues = p.getAllowedValues();
    if (allowedValues != null)
    {
      boolean found = false;
      for (final Object allowedValue : allowedValues)
      {
        if (dateValue.equals(allowedValue))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_ALLOWED.get(
                                     p.getDisplayName(), dateValue.toString()));
      }
    }

    return dateValue;
  }



  /**
   * Parses the provided set of values for the associated task property as a
   * {@code Long}.
   *
   * @param  p             The task property with which the values are
   *                       associated.
   * @param  values        The provided values for the task property.
   * @param  defaultValue  The default value to use if the provided object array
   *                       is empty.
   *
   * @return  The parsed {@code Long} value.
   *
   * @throws  TaskException  If there is a problem with the provided values.
   */
  protected static Long parseLong(final TaskProperty p,
                                  final List<Object> values,
                                  final Long defaultValue)
            throws TaskException
  {
    // Check to see if any values were provided.  If not, then it may or may not
    // be a problem.
    if (values.isEmpty())
    {
      if (p.isRequired())
      {
        throw new TaskException(ERR_TASK_REQUIRED_PROPERTY_WITHOUT_VALUES.get(
                                     p.getDisplayName()));
      }
      else
      {
        return defaultValue;
      }
    }

    // If there were multiple values, then that's always an error.
    if (values.size() > 1)
    {
      throw new TaskException(ERR_TASK_PROPERTY_NOT_MULTIVALUED.get(
                                   p.getDisplayName()));
    }

    // Make sure that the value can be interpreted as a Long.
    final Long longValue;
    final Object o = values.get(0);
    if (o instanceof Long)
    {
      longValue = (Long) o;
    }
    else if (o instanceof Number)
    {
      longValue = ((Number) o).longValue();
    }
    else if (o instanceof String)
    {
      try
      {
        longValue = Long.parseLong((String) o);
      }
      catch (final Exception e)
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_LONG.get(
                                     p.getDisplayName()), e);
      }
    }
    else
    {
      throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_LONG.get(
                                   p.getDisplayName()));
    }

    // If the task property has a set of allowed values, then make sure that the
    // provided value is acceptable.
    final Object[] allowedValues = p.getAllowedValues();
    if (allowedValues != null)
    {
      boolean found = false;
      for (final Object allowedValue : allowedValues)
      {
        if (longValue.equals(allowedValue))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_ALLOWED.get(
                                     p.getDisplayName(), longValue.toString()));
      }
    }

    return longValue;
  }



  /**
   * Parses the provided set of values for the associated task property as a
   * {@code String}.
   *
   * @param  p             The task property with which the values are
   *                       associated.
   * @param  values        The provided values for the task property.
   * @param  defaultValue  The default value to use if the provided object array
   *                       is empty.
   *
   * @return  The parsed {@code String} value.
   *
   * @throws  TaskException  If there is a problem with the provided values.
   */
  protected static String parseString(final TaskProperty p,
                                      final List<Object> values,
                                      final String defaultValue)
            throws TaskException
  {
    // Check to see if any values were provided.  If not, then it may or may not
    // be a problem.
    if (values.isEmpty())
    {
      if (p.isRequired())
      {
        throw new TaskException(ERR_TASK_REQUIRED_PROPERTY_WITHOUT_VALUES.get(
                                     p.getDisplayName()));
      }
      else
      {
        return defaultValue;
      }
    }

    // If there were multiple values, then that's always an error.
    if (values.size() > 1)
    {
      throw new TaskException(ERR_TASK_PROPERTY_NOT_MULTIVALUED.get(
                                   p.getDisplayName()));
    }

    // Make sure that the value is a String.
    final String valueStr;
    final Object o = values.get(0);
    if (o instanceof String)
    {
      valueStr = (String) o;
    }
    else if (values.get(0) instanceof CharSequence)
    {
      valueStr = o.toString();
    }
    else
    {
      throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_STRING.get(
                                   p.getDisplayName()));
    }

    // If the task property has a set of allowed values, then make sure that the
    // provided value is acceptable.
    final Object[] allowedValues = p.getAllowedValues();
    if (allowedValues != null)
    {
      boolean found = false;
      for (final Object allowedValue : allowedValues)
      {
        final String s = (String) allowedValue;
        if (valueStr.equalsIgnoreCase(s))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_ALLOWED.get(
                                     p.getDisplayName(), valueStr));
      }
    }

    return valueStr;
  }



  /**
   * Parses the provided set of values for the associated task property as a
   * {@code String} array.
   *
   * @param  p              The task property with which the values are
   *                        associated.
   * @param  values         The provided values for the task property.
   * @param  defaultValues  The set of default values to use if the provided
   *                        object array is empty.
   *
   * @return  The parsed {@code String} values.
   *
   * @throws  TaskException  If there is a problem with the provided values.
   */
  protected static String[] parseStrings(final TaskProperty p,
                                         final List<Object> values,
                                         final String[] defaultValues)
            throws TaskException
  {
    // Check to see if any values were provided.  If not, then it may or may not
    // be a problem.
    if (values.isEmpty())
    {
      if (p.isRequired())
      {
        throw new TaskException(ERR_TASK_REQUIRED_PROPERTY_WITHOUT_VALUES.get(
                                     p.getDisplayName()));
      }
      else
      {
        return defaultValues;
      }
    }


    // Iterate through each of the values and perform appropriate validation for
    // them.
    final String[] stringValues = new String[values.size()];
    for (int i=0; i < values.size(); i++)
    {
      final Object o = values.get(i);

      // Make sure that the value is a String.
      final String valueStr;
      if (o instanceof String)
      {
        valueStr = (String) o;
      }
      else if (o instanceof CharSequence)
      {
        valueStr = o.toString();
      }
      else
      {
        throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_STRING.get(
                                     p.getDisplayName()));
      }

      // If the task property has a set of allowed values, then make sure that
      // the provided value is acceptable.
      final Object[] allowedValues = p.getAllowedValues();
      if (allowedValues != null)
      {
        boolean found = false;
        for (final Object allowedValue : allowedValues)
        {
          final String s = (String) allowedValue;
          if (valueStr.equalsIgnoreCase(s))
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          throw new TaskException(ERR_TASK_PROPERTY_VALUE_NOT_ALLOWED.get(
                                       p.getDisplayName(), valueStr));
        }
      }

      stringValues[i] = valueStr;
    }

    return stringValues;
  }



  /**
   * Retrieves a list of the additional object classes (other than the base
   * "top" and "ds-task" classes) that should be included when creating new task
   * entries of this type.
   *
   * @return  A list of the additional object classes that should be included in
   *          new task entries of this type, or an empty list if there do not
   *          need to be any additional classes.
   */
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.emptyList();
  }



  /**
   * Retrieves a list of the additional attributes (other than attributes common
   * to all task types) that should be included when creating new task entries
   * of this type.
   *
   * @return  A list of the additional attributes that should be included in new
   *          task entries of this type, or an empty list if there do not need
   *          to be any additional attributes.
   */
  protected List<Attribute> getAdditionalAttributes()
  {
    return Collections.emptyList();
  }



  /**
   * Decodes the provided entry as a scheduled task.  An attempt will be made to
   * decode the entry as an appropriate subclass if possible, but it will fall
   * back to a generic task if it is not possible to decode as a more specific
   * task type.
   *
   * @param  entry  The entry to be decoded.
   *
   * @return  The decoded task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         scheduled task.
   */
  public static Task decodeTask(final Entry entry)
         throws TaskException
  {
    final String taskClass = entry.getAttributeValue(ATTR_TASK_CLASS);
    if (taskClass == null)
    {
      throw new TaskException(ERR_TASK_NO_CLASS.get(entry.getDN()));
    }

    try
    {
      if (taskClass.equals(AddSchemaFileTask.ADD_SCHEMA_FILE_TASK_CLASS))
      {
        return new AddSchemaFileTask(entry);
      }
      else if (taskClass.equals(AlertTask.ALERT_TASK_CLASS))
      {
        return new AlertTask(entry);
      }
      else if (taskClass.equals(AuditDataSecurityTask.
                    AUDIT_DATA_SECURITY_TASK_CLASS))
      {
        return new AuditDataSecurityTask(entry);
      }
      else if (taskClass.equals(BackupTask.BACKUP_TASK_CLASS))
      {
        return new BackupTask(entry);
      }
      else if (taskClass.equals(
                    DisconnectClientTask.DISCONNECT_CLIENT_TASK_CLASS))
      {
        return new DisconnectClientTask(entry);
      }
      else if (taskClass.equals(DumpDBDetailsTask.DUMP_DB_DETAILS_TASK_CLASS))
      {
        return new DumpDBDetailsTask(entry);
      }
      else if (taskClass.equals(
                    EnterLockdownModeTask.ENTER_LOCKDOWN_MODE_TASK_CLASS))
      {
        return new EnterLockdownModeTask(entry);
      }
      else if (taskClass.equals(ExportTask.EXPORT_TASK_CLASS))
      {
        return new ExportTask(entry);
      }
      else if (taskClass.equals(GroovyScriptedTask.GROOVY_SCRIPTED_TASK_CLASS))
      {
        return new GroovyScriptedTask(entry);
      }
      else if (taskClass.equals(ImportTask.IMPORT_TASK_CLASS))
      {
        return new ImportTask(entry);
      }
      else if (taskClass.equals(
                    LeaveLockdownModeTask.LEAVE_LOCKDOWN_MODE_TASK_CLASS))
      {
        return new LeaveLockdownModeTask(entry);
      }
      else if (taskClass.equals(RebuildTask.REBUILD_TASK_CLASS))
      {
        return new RebuildTask(entry);
      }
      else if (taskClass.equals(
                    ReEncodeEntriesTask.RE_ENCODE_ENTRIES_TASK_CLASS))
      {
        return new ReEncodeEntriesTask(entry);
      }
      else if (taskClass.equals(RefreshEncryptionSettingsTask.
                    REFRESH_ENCRYPTION_SETTINGS_TASK_CLASS))
      {
        return new RefreshEncryptionSettingsTask(entry);
      }
      else if (taskClass.equals(
           ReloadGlobalIndexTask.RELOAD_GLOBAL_INDEX_TASK_CLASS))
      {
        return new ReloadGlobalIndexTask(entry);
      }
      else if (taskClass.equals(RestoreTask.RESTORE_TASK_CLASS))
      {
        return new RestoreTask(entry);
      }
      else if (taskClass.equals(RotateLogTask.ROTATE_LOG_TASK_CLASS))
      {
        return new RotateLogTask(entry);
      }
      else if (taskClass.equals(SearchTask.SEARCH_TASK_CLASS))
      {
        return new SearchTask(entry);
      }
      else if (taskClass.equals(ShutdownTask.SHUTDOWN_TASK_CLASS))
      {
        return new ShutdownTask(entry);
      }
      else if (taskClass.equals(SynchronizeEncryptionSettingsTask.
                    SYNCHRONIZE_ENCRYPTION_SETTINGS_TASK_CLASS))
      {
        return new SynchronizeEncryptionSettingsTask(entry);
      }
      else if (taskClass.equals(ThirdPartyTask.THIRD_PARTY_TASK_CLASS))
      {
        return new ThirdPartyTask(entry);
      }
    }
    catch (final TaskException te)
    {
      debugException(te);
    }

    return new Task(entry);
  }



  /**
   * Retrieves a list of task properties that may be provided when scheduling
   * any type of task.  This includes:
   * <UL>
   *   <LI>The task ID</LI>
   *   <LI>The scheduled start time</LI>
   *   <LI>The task IDs of any tasks on which this task is dependent</LI>
   *   <LI>The action to take for this task if any of its dependencies fail</LI>
   *   <LI>The addresses of users to notify when this task completes</LI>
   *   <LI>The addresses of users to notify if this task fails</LI>
   * </UL>
   *
   * @return  A list of task properties that may be provided when scheduling any
   *          type of task.
   */
  public static List<TaskProperty> getCommonTaskProperties()
  {
    final List<TaskProperty> taskList = Arrays.asList(
         PROPERTY_TASK_ID,
         PROPERTY_SCHEDULED_START_TIME,
         PROPERTY_DEPENDENCY_ID,
         PROPERTY_FAILED_DEPENDENCY_ACTION,
         PROPERTY_NOTIFY_ON_COMPLETION,
         PROPERTY_NOTIFY_ON_ERROR);

    return Collections.unmodifiableList(taskList);
  }



  /**
   * Retrieves a list of task-specific properties that may be provided when
   * scheduling a task of this type.  This method should be overridden by
   * subclasses in order to provide an appropriate set of properties.
   *
   * @return  A list of task-specific properties that may be provided when
   *          scheduling a task of this type.
   */
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.emptyList();
  }



  /**
   * Retrieves the values of the task properties for this task.  The data type
   * of the values will vary based on the data type of the corresponding task
   * property and may be one of the following types:  {@code Boolean},
   * {@code Date}, {@code Long}, or {@code String}.  Task properties which do
   * not have any values will be included in the map with an empty value list.
   * <BR><BR>
   * Note that subclasses which have additional task properties should override
   * this method and return a map which contains both the property values from
   * this class (obtained from {@code super.getTaskPropertyValues()} and the
   * values of their own task-specific properties.
   *
   * @return  A map of the task property values for this task.
   */
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>();

    props.put(PROPERTY_TASK_ID,
              Collections.<Object>unmodifiableList(Arrays.asList(taskID)));

    if (scheduledStartTime == null)
    {
      props.put(PROPERTY_SCHEDULED_START_TIME, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_SCHEDULED_START_TIME,
                Collections.<Object>unmodifiableList(Arrays.asList(
                     scheduledStartTime)));
    }

    props.put(PROPERTY_DEPENDENCY_ID,
              Collections.<Object>unmodifiableList(dependencyIDs));

    if (failedDependencyAction == null)
    {
      props.put(PROPERTY_FAILED_DEPENDENCY_ACTION, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_FAILED_DEPENDENCY_ACTION,
                Collections.<Object>unmodifiableList(Arrays.asList(
                     failedDependencyAction.getName())));
    }

    props.put(PROPERTY_NOTIFY_ON_COMPLETION,
              Collections.<Object>unmodifiableList(notifyOnCompletion));

    props.put(PROPERTY_NOTIFY_ON_ERROR,
              Collections.<Object>unmodifiableList(notifyOnError));

    return Collections.unmodifiableMap(props);
  }



  /**
   * Retrieves a string representation of this task.
   *
   * @return  A string representation of this task.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this task to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 provided.
   */
  public final void toString(final StringBuilder buffer)
  {
    buffer.append("Task(name='");
    buffer.append(getTaskName());
    buffer.append("', className='");
    buffer.append(taskClassName);
    buffer.append(", properties={");

    boolean added = false;
    for (final Map.Entry<TaskProperty,List<Object>> e :
         getTaskPropertyValues().entrySet())
    {
      if (added)
      {
        buffer.append(", ");
      }
      else
      {
        added = true;
      }

      buffer.append(e.getKey().getAttributeName());
      buffer.append("={");

      final Iterator<Object> iterator = e.getValue().iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(String.valueOf(iterator.next()));
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    buffer.append("})");
  }
}
