/*
 * Copyright 2010-2018 Ping Identity Corporation
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
import static com.unboundid.util.Validator.*;



/**
 * This class defines a Directory Server task that can be used to dump
 * information about the contents of a backend which stores its data in a
 * Berkeley DB Java Edition database.  It reports information about the total
 * number of keys, total and average key size, and total an average value size
 * for all of the databases in the environment, and the percentage of the total
 * live data size contained in each database.
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
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>The backend ID of the backend for to be examined.  The specified
 *       backend must be enabled and must store its contents in the Berkeley DB
 *       Java Edition.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DumpDBDetailsTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the dump DB
   * details task.
   */
  static final String DUMP_DB_DETAILS_TASK_CLASS =
       "com.unboundid.directory.server.tasks.DumpDBDetailsTask";



  /**
   * The name of the attribute used to specify the backend ID of the target
   * backend.
   */
  private static final String ATTR_BACKEND_ID =
       "ds-task-dump-db-backend-id";



  /**
   * The name of the object class used in dump DB details task entries.
   */
  private static final String OC_DUMP_DB_DETAILS_TASK = "ds-task-dump-db";



  /**
   * The task property that will be used for the backend ID.
   */
  private static final TaskProperty PROPERTY_BACKEND_ID =
     new TaskProperty(ATTR_BACKEND_ID,
          INFO_DUMP_DB_DISPLAY_NAME_BACKEND_ID.get(),
          INFO_DUMP_DB_DESCRIPTION_BACKEND_ID.get(), String.class, true,
          false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7267871080385864231L;



  // The name of the backend to be examined.
  private final String backendID;



  /**
   * Creates a new uninitialized dump DB details task instance which should only
   * be used for obtaining general information about this task, including the
   * task name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public DumpDBDetailsTask()
  {
    backendID = null;
  }




  /**
   * Creates a new dump DB details task to examine the specified backend.
   *
   * @param  taskID     The task ID to use for this task.  If it is {@code null}
   *                    then a UUID will be generated for use as the task ID.
   * @param  backendID  The backend ID for the backend to examine.  It must not
   *                    be {@code null}.
   */
  public DumpDBDetailsTask(final String taskID, final String backendID)
  {
    this(taskID, backendID, null, null, null, null, null);
  }



  /**
   * Creates a new dump DB details task to examine the specified backend.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  backendID               The backend ID for the backend to examine.
   *                                 It must not be {@code null}.
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
  public DumpDBDetailsTask(final String taskID, final String backendID,
                           final Date scheduledStartTime,
                           final List<String> dependencyIDs,
                           final FailedDependencyAction failedDependencyAction,
                           final List<String> notifyOnCompletion,
                           final List<String> notifyOnError)
  {
    super(taskID, DUMP_DB_DETAILS_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnCompletion, notifyOnError);

    ensureNotNull(backendID);

    this.backendID = backendID;
  }



  /**
   * Creates a new dump DB details task from the provided entry.
   *
   * @param  entry  The entry to use to create this dump DB details task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a dump DB
   *                         details task entry.
   */
  public DumpDBDetailsTask(final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the backend ID.  It must be present.
    backendID = entry.getAttributeValue(ATTR_BACKEND_ID);
    if (backendID == null)
    {
      throw new TaskException(ERR_DUMP_DB_ENTRY_MISSING_BACKEND_ID.get(
           getTaskEntryDN(), ATTR_BACKEND_ID));
    }
  }



  /**
   * Creates a new dump DB details task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid dump DB details task.
   */
  public DumpDBDetailsTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(DUMP_DB_DETAILS_TASK_CLASS, properties);

    String id = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BACKEND_ID))
      {
        id = parseString(p, values, id);
      }
    }

    if (id == null)
    {
      throw new TaskException(ERR_DUMP_DB_ENTRY_MISSING_BACKEND_ID.get(
           getTaskEntryDN(), ATTR_BACKEND_ID));
    }

    backendID = id;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_DUMP_DB.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_DUMP_DB.get();
  }



  /**
   * Retrieves the backend ID of the backend to examine.
   *
   * @return  The backend ID of the backend to examine.
   */
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_DUMP_DB_DETAILS_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    return Arrays.asList(new Attribute(ATTR_BACKEND_ID, backendID));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(PROPERTY_BACKEND_ID));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>(1);

    props.put(PROPERTY_BACKEND_ID, Collections.<Object>unmodifiableList(
         Arrays.asList(backendID)));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
