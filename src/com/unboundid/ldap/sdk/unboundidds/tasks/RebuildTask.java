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
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to generate
 * and/or rebuild one or more indexes a Berkeley DB Java Edition backend.
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
 *   <LI>The backend base DN for which to perform the index rebuild.  This
 *       must be provided when scheduling a rebuild task.</LI>
 *   <LI>The names of the indexes to be built.  At least one index name must be
 *       provided when scheduling a rebuild task.</LI>
 *   <LI>The maximum number of concurrent threads that should be used to perform
 *       the processing.  A value of zero indicates that there is no limit.</LI>
 * </UL>

 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RebuildTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the rebuild
   * task.
   */
  @NotNull static final String REBUILD_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RebuildTask";



  /**
   * The name of the attribute used to specify the base DN for which to rebuild
   * the specified indexes.
   */
  @NotNull private static final String ATTR_BASE_DN = "ds-task-rebuild-base-dn";



  /**
   * The name of the attribute used to specify the names of the indexes to
   * rebuild.
   */
  @NotNull private static final String ATTR_INDEX = "ds-task-rebuild-index";



  /**
   * The name of the attribute used to specify the maximum number of concurrent
   * threads to use to perform the rebuild.
   */
  @NotNull private static final String ATTR_MAX_THREADS =
       "ds-task-rebuild-max-threads";



  /**
   * The name of the object class used in rebuild task entries.
   */
  @NotNull private static final String OC_REBUILD_TASK = "ds-task-rebuild";



  /**
   * The task property for the base DN.
   */
  @NotNull private static final TaskProperty PROPERTY_BASE_DN =
       new TaskProperty(ATTR_BASE_DN, INFO_DISPLAY_NAME_BASE_DN_REBUILD.get(),
                        INFO_DESCRIPTION_BASE_DN_REBUILD.get(), String.class,
                        true, false, false);



  /**
   * The task property for the index names.
   */
  @NotNull private static final TaskProperty PROPERTY_INDEX =
       new TaskProperty(ATTR_INDEX, INFO_DISPLAY_NAME_INDEX_REBUILD.get(),
                        INFO_DESCRIPTION_INDEX_REBUILD.get(), String.class,
                        true, true, false);



  /**
   * The task property for the max threads value.
   */
  @NotNull private static final TaskProperty PROPERTY_MAX_THREADS =
       new TaskProperty(ATTR_MAX_THREADS,
                        INFO_DISPLAY_NAME_MAX_THREADS_REBUILD.get(),
                        INFO_DESCRIPTION_MAX_THREADS_REBUILD.get(), Long.class,
                        false, false, true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6015907901926792443L;



  // The maximum number of threads to use to rebuild indexes.
  private final int maxThreads;

  // The base DN for which to rebuild indexes.
  @NotNull private final String baseDN;

  // The names of the indexes to rebuild.
  @NotNull private final List<String> indexes;



  /**
   * Creates a new uninitialized rebuild task instance which should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public RebuildTask()
  {
    baseDN     = null;
    maxThreads = -1;
    indexes    = null;
  }



  /**
   * Creates a new rebuild task with the provided information.
   *
   * @param  taskID   The task ID to use for this task.  If it is {@code null}
   *                  then a UUID will be generated for use as the task ID.
   * @param  baseDN   The base DN for which to rebuild the index.  It must refer
   *                  to a base DN for a Berkeley DB Java Edition backend.  It
   *                  must not be {@code null}.
   * @param  indexes  A list containing the names of the indexes to rebuild.  It
   *                  must not be {@code null} or empty.
   */
  public RebuildTask(@Nullable final String taskID,
                     @NotNull final String baseDN,
                     @NotNull final List<String> indexes)
  {
    this(taskID, baseDN, indexes, -1, null, null, null, null, null);
  }



  /**
   * Creates a new rebuild task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  baseDN                  The base DN for which to rebuild the index.
   *                                 It must refer to a base DN for a Berkeley
   *                                 DB Java Edition backend.  It must not be
   *                                 {@code null}.
   * @param  indexes                 A list containing the names of the indexes
   *                                 to rebuild.  It must not be {@code null} or
   *                                 empty.
   * @param  maxThreads              The maximum number of concurrent threads to
   *                                 use while performing the rebuild.  A value
   *                                 less than or equal to zero indicates that
   *                                 there is no limit to the number of threads
   *                                 that may be used.
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
  public RebuildTask(@Nullable final String taskID,
              @NotNull final String baseDN,
              @NotNull final List<String> indexes,
              final int maxThreads,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, baseDN, indexes, maxThreads, scheduledStartTime, dependencyIDs,
         failedDependencyAction, null, notifyOnCompletion, null, notifyOnError,
         null, null, null);
  }



  /**
   * Creates a new rebuild task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  baseDN                  The base DN for which to rebuild the index.
   *                                 It must refer to a base DN for a Berkeley
   *                                 DB Java Edition backend.  It must not be
   *                                 {@code null}.
   * @param  indexes                 A list containing the names of the indexes
   *                                 to rebuild.  It must not be {@code null} or
   *                                 empty.
   * @param  maxThreads              The maximum number of concurrent threads to
   *                                 use while performing the rebuild.  A value
   *                                 less than or equal to zero indicates that
   *                                 there is no limit to the number of threads
   *                                 that may be used.
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
  public RebuildTask(@Nullable final String taskID,
              @NotNull final String baseDN,
              @NotNull final List<String> indexes,
              final int maxThreads,
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
    super(taskID, REBUILD_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    Validator.ensureNotNull(baseDN, indexes);
    Validator.ensureFalse(indexes.isEmpty(),
         "RebuildTask.indexes must not be empty.");

    this.baseDN     = baseDN;
    this.indexes    = Collections.unmodifiableList(indexes);
    this.maxThreads = maxThreads;
  }



  /**
   * Creates a new rebuild task from the provided entry.
   *
   * @param  entry  The entry to use to create this rebuild task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a rebuild
   *                         task entry.
   */
  public RebuildTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the base DN.  It must be present.
    baseDN = entry.getAttributeValue(ATTR_BASE_DN);
    if (baseDN == null)
    {
      throw new TaskException(ERR_REBUILD_TASK_NO_BASE_DN.get(
                                   getTaskEntryDN()));
    }


    // Get the names of the indexes to rebuild.  It must be present.
    final String[] indexArray = entry.getAttributeValues(ATTR_INDEX);
    if ((indexArray == null) || (indexArray.length == 0))
    {
      throw new TaskException(ERR_REBUILD_TASK_NO_INDEXES.get(
                                   getTaskEntryDN()));
    }
    else
    {
      indexes = Collections.unmodifiableList(Arrays.asList(indexArray));
    }


    // Get the maximum number of threads to use.
    final String threadsStr = entry.getAttributeValue(ATTR_MAX_THREADS);
    if (threadsStr == null)
    {
      maxThreads = -1;
    }
    else
    {
      try
      {
        maxThreads = Integer.parseInt(threadsStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new TaskException(ERR_REBUILD_TASK_INVALID_MAX_THREADS.get(
                                     getTaskEntryDN(), threadsStr), e);
      }
    }
  }



  /**
   * Creates a new rebuild task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid rebuild task.
   */
  public RebuildTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(REBUILD_TASK_CLASS, properties);

    long     t = -1;
    String   b = null;
    String[] i = null;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BASE_DN))
      {
        b = parseString(p, values, b);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INDEX))
      {
        i = parseStrings(p, values, i);
      }
      else if (attrName.equalsIgnoreCase(ATTR_MAX_THREADS))
      {
        t = parseLong(p, values, t);
      }
    }

    if (b == null)
    {
      throw new TaskException(ERR_REBUILD_TASK_NO_BASE_DN.get(
                                   getTaskEntryDN()));
    }

    if (i == null)
    {
      throw new TaskException(ERR_REBUILD_TASK_NO_INDEXES.get(
                                   getTaskEntryDN()));
    }

    baseDN     = b;
    indexes    = Collections.unmodifiableList(Arrays.asList(i));
    maxThreads = (int) t;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_REBUILD.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
    @NotNull()
public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_REBUILD.get();
  }



  /**
   * Retrieves the base DN for which to rebuild the specified indexes.
   *
   * @return  The base DN for which to rebuild the specified indexes.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the names of the indexes to be rebuilt.
   *
   * @return  The names of the indexes to be rebuilt.
   */
  @NotNull()
  public List<String> getIndexNames()
  {
    return indexes;
  }



  /**
   * Retrieves the maximum number of concurrent threads that should be used when
   * rebuilding the indexes.
   *
   * @return  The maximum number of concurrent threads that should be used when
   *          rebuilding the indexes, or a value less than or equal to zero if
   *          there is no limit on the number of threads that may be used.
   */
  public int getMaxRebuildThreads()
  {
    return maxThreads;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_REBUILD_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(3);

    attrs.add(new Attribute(ATTR_BASE_DN, baseDN));
    attrs.add(new Attribute(ATTR_INDEX, indexes));

    if (maxThreads > 0)
    {
      attrs.add(new Attribute(ATTR_MAX_THREADS, String.valueOf(maxThreads)));
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
    final List<TaskProperty> propList = Arrays.asList(
         PROPERTY_BASE_DN,
         PROPERTY_INDEX,
         PROPERTY_MAX_THREADS);

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

    props.put(PROPERTY_BASE_DN,
              Collections.<Object>singletonList(baseDN));

    props.put(PROPERTY_INDEX,
              Collections.<Object>unmodifiableList(indexes));

    props.put(PROPERTY_MAX_THREADS,
              Collections.<Object>singletonList((long) maxThreads));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
