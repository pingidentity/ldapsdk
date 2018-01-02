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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to cause the
 * server to enter lockdown mode, in which case it will only allow requests
 * from users with the lockdown-mode privilege.  Lockdown mode is intended to
 * allow administrators to perform operations with the server online but without
 * worrying about the impact that those operations may have on other users.  In
 * In some special cases, the server may place itself in lockdown mode as a
 * defense mechanism rather than risking the exposure of sensitive information.
 * For example, if the server detects any malformed access control rules at
 * startup, then it will place itself in lockdown mode rather than attempt to
 * run without that rule in effect since it could have been intended to prevent
 * unauthorized users from accessing certain data.
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
 * The enter lockdown mode task does not have any task-specific properties.  See
 * the {@link LeaveLockdownModeTask} class for the corresponding mechanism to
 * bring the server out of lockdown mode.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EnterLockdownModeTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the enter
   * lockdown mode task.
   */
  static final String ENTER_LOCKDOWN_MODE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.EnterLockdownModeTask";



  /**
   * The name of the attribute used to specify the reason for putting the server
   * into lockdown mode.
   */
  private static final String ATTR_ENTER_LOCKDOWN_REASON =
       "ds-task-enter-lockdown-reason";



  /**
   * The task property for the enter-lockdown reason.
   */
  private static final TaskProperty PROPERTY_ENTER_LOCKDOWN_REASON =
       new TaskProperty(ATTR_ENTER_LOCKDOWN_REASON,
                        INFO_DISPLAY_NAME_ENTER_LOCKDOWN_REASON.get(),
                        INFO_DESCRIPTION_ENTER_LOCKDOWN_REASON.get(),
                        String.class, false, false, false);



  /**
   * The name of the object class used in enter-lockdown-mode task entries.
   */
  private static final String OC_ENTER_LOCKDOWN_MODE_TASK =
      "ds-task-enter-lockdown-mode";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4104020769734351458L;



  // The reason for entering lockdown mode.
  private final String reason;



  /**
   * Creates a new uninitialized enter lockdown mode task instance which should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  public EnterLockdownModeTask()
  {
    reason = null;
  }



  /**
   * Creates a new enter lockdown mode task with the specified task ID.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   */
  public EnterLockdownModeTask(final String taskID)
  {
    this(taskID, null);
  }



  /**
   * Creates a new enter lockdown mode task with the specified task ID.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   * @param  reason  The user-specified reason for entering lockdown mode. This
   *                 may be {@code null}.
   */
  public EnterLockdownModeTask(final String taskID, final String reason)
  {
    this(taskID, reason, null, null, null, null, null);
  }



  /**
   * Creates a new enter lockdown mode task with the provided information.
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
  public EnterLockdownModeTask(final String taskID,
              final Date scheduledStartTime, final List<String> dependencyIDs,
              final FailedDependencyAction failedDependencyAction,
              final List<String> notifyOnCompletion,
              final List<String> notifyOnError)
  {
    this(taskID, null, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnCompletion, notifyOnError);
  }



  /**
   * Creates a new enter lockdown mode task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  reason                  The user-specified reason for entering
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
  public EnterLockdownModeTask(final String taskID, final String reason,
              final Date scheduledStartTime, final List<String> dependencyIDs,
              final FailedDependencyAction failedDependencyAction,
              final List<String> notifyOnCompletion,
              final List<String> notifyOnError)
  {
    super(taskID, ENTER_LOCKDOWN_MODE_TASK_CLASS, scheduledStartTime,
          dependencyIDs, failedDependencyAction, notifyOnCompletion,
          notifyOnError);

    this.reason = reason;
  }



  /**
   * Creates a new enter lockdown mode task from the provided entry.
   *
   * @param  entry  The entry to use to create this enter lockdown mode task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as an enter
   *                         lockdown mode task entry.
   */
  public EnterLockdownModeTask(final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the "reason" string if it is present.
    reason = entry.getAttributeValue(ATTR_ENTER_LOCKDOWN_REASON);
  }



  /**
   * Creates a new enter lockdown mode task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid enter lockdown mode task.
   */
  public EnterLockdownModeTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(ENTER_LOCKDOWN_MODE_TASK_CLASS, properties);

    String r = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
            properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_ENTER_LOCKDOWN_REASON))
      {
        r = parseString(p, values, null);
        break;
      }
    }

    reason = r;
  }



  /**
   * Retrieves the user-specified reason why the server is entering lockdown
   * mode.
   *
   * @return  The reason the server is entering lockdown mode, or {@code null}
   *          if none was specified.
   */
  public String getReason()
  {
    return reason;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_ENTER_LOCKDOWN_MODE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_ENTER_LOCKDOWN_MODE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_ENTER_LOCKDOWN_MODE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<Attribute>(1);
    if(reason != null)
    {
      attrs.add(new Attribute(ATTR_ENTER_LOCKDOWN_REASON, reason));
    }
    return attrs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    final List<TaskProperty> propList =
              Arrays.asList(PROPERTY_ENTER_LOCKDOWN_REASON);

    return Collections.unmodifiableList(propList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>();

    if (reason != null)
    {
      props.put(PROPERTY_ENTER_LOCKDOWN_REASON,
              Collections.<Object>unmodifiableList(Arrays.asList(reason)));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
