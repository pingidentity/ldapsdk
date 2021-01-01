/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
 * This class defines a Directory Proxy Server task that can be used to reload
 * the contents of the global index.
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
 *   <LI>The base DN for the entry-balancing request processor.</LI>
 *   <LI>An optional set of attributes for which to reload the index
 *       information.</LI>
 *   <LI>A flag indicating whether to perform the reload in the background.</LI>
 *   <LI>A flag indicating whether to reload entries from backend Directory
 *       Server instances rather than a peer Directory Proxy Server
 *       instance.</LI>
 *   <LI>An optional maximum number of entries per second to access when
 *       priming.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReloadGlobalIndexTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the re-encode
   * entries task.
   */
  @NotNull static final String RELOAD_GLOBAL_INDEX_TASK_CLASS =
       "com.unboundid.directory.proxy.tasks.ReloadTask";



  /**
   * The name of the attribute used to indicate whether the reload should be
   * done in the background.
   */
  @NotNull private static final String ATTR_BACKGROUND_RELOAD =
       "ds-task-reload-background";



  /**
   * The name of the attribute used to specify the base DN for the
   * entry-balancing request processor.
   */
  @NotNull private static final String ATTR_BASE_DN = "ds-task-reload-base-dn";



  /**
   * The name of the attribute used to specify the names of the attributes for
   * which to reload the indexes.
   */
  @NotNull private static final String ATTR_INDEX_NAME =
       "ds-task-reload-index-name";



  /**
   * The name of the attribute used to specify a target rate limit for the
   * maximum number of entries per second.
   */
  @NotNull private static final String ATTR_MAX_ENTRIES_PER_SECOND =
       "ds-task-search-entry-per-second";



  /**
   * The name of the attribute used to indicate whether the data should be
   * loaded from backend Directory Server instances rather than a peer Directory
   * Proxy Server instance.
   */
  @NotNull private static final String ATTR_RELOAD_FROM_DS =
       "ds-task-reload-from-ds";



  /**
   * The name of the object class used in reload global index task entries.
   */
  @NotNull private static final String OC_RELOAD_GLOBAL_INDEX_TASK =
       "ds-task-reload-index";



  /**
   * The task property that will be used for the request processor base DN.
   */
  @NotNull private static final TaskProperty PROPERTY_BACKGROUND_RELOAD =
       new TaskProperty(ATTR_BACKGROUND_RELOAD,
            INFO_DISPLAY_NAME_RELOAD_GLOBAL_INDEX_BACKGROUND.get(),
            INFO_DESCRIPTION_RELOAD_GLOBAL_INDEX_BACKGROUND.get(),
            Boolean.class, false, false, false);



  /**
   * The task property that will be used for the request processor base DN.
   */
  @NotNull private static final TaskProperty PROPERTY_BASE_DN =
       new TaskProperty(ATTR_BASE_DN,
            INFO_DISPLAY_NAME_RELOAD_GLOBAL_INDEX_BASE_DN.get(),
            INFO_DESCRIPTION_RELOAD_GLOBAL_INDEX_BASE_DN.get(), String.class,
            true, false, false);



  /**
   * The task property that will be used for the request processor base DN.
   */
  @NotNull private static final TaskProperty PROPERTY_INDEX_NAME =
       new TaskProperty(ATTR_INDEX_NAME,
            INFO_DISPLAY_NAME_RELOAD_GLOBAL_INDEX_ATTR_NAME.get(),
            INFO_DESCRIPTION_RELOAD_GLOBAL_INDEX_ATTR_NAME.get(), String.class,
            false, true, false);



  /**
   * The task property that will be used for the request processor base DN.
   */
  @NotNull private static final TaskProperty PROPERTY_MAX_ENTRIES_PER_SECOND =
       new TaskProperty(ATTR_MAX_ENTRIES_PER_SECOND,
            INFO_DISPLAY_NAME_RELOAD_GLOBAL_INDEX_MAX_ENTRIES_PER_SECOND.get(),
            INFO_DESCRIPTION_RELOAD_GLOBAL_INDEX_MAX_ENTRIES_PER_SECOND.get(),
            Long.class, false, false, false);



  /**
   * The task property that will be used for the request processor base DN.
   */
  @NotNull static final TaskProperty PROPERTY_RELOAD_FROM_DS = new TaskProperty(
       ATTR_RELOAD_FROM_DS,
       INFO_DISPLAY_NAME_RELOAD_GLOBAL_INDEX_RELOAD_FROM_DS.get(),
       INFO_DESCRIPTION_RELOAD_GLOBAL_INDEX_RELOAD_FROM_DS.get(), Boolean.class,
       false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9152807987055252560L;



  // Indicates whether to reload from backend Directory Server instances.
  @Nullable private final Boolean reloadFromDS;

  // Indicates whether to reload in the background.
  @Nullable private final Boolean reloadInBackground;

  // The names of the indexes to reload.
  @NotNull private final List<String> indexNames;

  // The target maximum rate limit to use when loading entry data.
  @Nullable private final Long maxEntriesPerSecond;

  // The base DN for the entry-balancing request processor.
  @NotNull private final String baseDN;



  /**
   * Creates a new uninitialized reload global index task instance which should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  public ReloadGlobalIndexTask()
  {
    reloadFromDS        = null;
    reloadInBackground  = null;
    indexNames          = null;
    maxEntriesPerSecond = null;
    baseDN              = null;
  }



  /**
   * Creates a new reload global index task with the provided information.
   *
   * @param  taskID               The task ID to use for this task.  If it is
   *                              {@code null} then a UUID will be generated for
   *                              use as the task ID.
   * @param  baseDN               The base DN of the entry-balancing request
   *                              processor for which to reload index
   *                              information.
   * @param  indexNames           The names of the attributes for which to
   *                              reload index data.  This may be {@code null}
   *                              or empty to indicate that all indexes should
   *                              be reloaded.
   * @param  reloadFromDS         Indicates whether to load index data from
   *                              backend Directory Server instances rather than
   *                              a peer Directory Proxy Server instance.  This
   *                              may be {@code null} to indicate that the
   *                              Directory Proxy Server should automatically
   *                              select the appropriate source for obtaining
   *                              index data.
   * @param  reloadInBackground   Indicates whether to perform the reload in
   *                              the background, so that the task completes
   *                              immediately.
   * @param  maxEntriesPerSecond  The maximum target rate at which to reload
   *                              index data (in entries per second).  A value
   *                              of zero indicates no limit.  A value of
   *                              {@code null} indicates that the Directory
   *                              Proxy Server should attempt to determine the
   *                              limit based on its configuration.
   */
  public ReloadGlobalIndexTask(@Nullable final String taskID,
                               @NotNull final String baseDN,
                               @Nullable final List<String> indexNames,
                               @Nullable final Boolean reloadFromDS,
                               @Nullable final Boolean reloadInBackground,
                               @Nullable final Long maxEntriesPerSecond)
  {
    this(taskID, baseDN, indexNames, reloadFromDS, reloadInBackground,
         maxEntriesPerSecond, null, null, null, null, null);
  }



  /**
   * Creates a new reload global index task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  baseDN                  The base DN of the entry-balancing request
   *                                 processor for which to reload index
   *                                 information.
   * @param  indexNames              The names of the attributes for which to
   *                                 reload index data.  This may be
   *                                 {@code null} or empty to indicate that all
   *                                 indexes should be reloaded.
   * @param  reloadFromDS            Indicates whether to load index data from
   *                                 backend Directory Server instances rather
   *                                 than a peer Directory Proxy Server
   *                                 instance.  This may be {@code null} to
   *                                 indicate that the Directory Proxy Server
   *                                 should automatically select the appropriate
   *                                 source for obtaining index data.
   * @param  reloadInBackground      Indicates whether to perform the reload in
   *                                 the background, so that the task completes
   *                                 immediately.
   * @param  maxEntriesPerSecond     The maximum target rate at which to reload
   *                                 index data (in entries per second).  A
   *                                 value of zero indicates no limit.  A value
   *                                 of {@code null} indicates that the
   *                                 Directory Proxy Server should attempt to
   *                                 determine the limit based on its
   *                                 configuration.
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
  public ReloadGlobalIndexTask(@Nullable final String taskID,
              @NotNull final String baseDN,
              @Nullable final List<String> indexNames,
              @Nullable final Boolean reloadFromDS,
              @Nullable final Boolean reloadInBackground,
              @Nullable final Long maxEntriesPerSecond,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnError)
  {
    this(taskID, baseDN, indexNames, reloadFromDS, reloadInBackground,
         maxEntriesPerSecond, scheduledStartTime, dependencyIDs,
         failedDependencyAction, null, notifyOnCompletion, null,
         notifyOnError, null, null, null);
  }



  /**
   * Creates a new reload global index task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  baseDN                  The base DN of the entry-balancing request
   *                                 processor for which to reload index
   *                                 information.
   * @param  indexNames              The names of the attributes for which to
   *                                 reload index data.  This may be
   *                                 {@code null} or empty to indicate that all
   *                                 indexes should be reloaded.
   * @param  reloadFromDS            Indicates whether to load index data from
   *                                 backend Directory Server instances rather
   *                                 than a peer Directory Proxy Server
   *                                 instance.  This may be {@code null} to
   *                                 indicate that the Directory Proxy Server
   *                                 should automatically select the appropriate
   *                                 source for obtaining index data.
   * @param  reloadInBackground      Indicates whether to perform the reload in
   *                                 the background, so that the task completes
   *                                 immediately.
   * @param  maxEntriesPerSecond     The maximum target rate at which to reload
   *                                 index data (in entries per second).  A
   *                                 value of zero indicates no limit.  A value
   *                                 of {@code null} indicates that the
   *                                 Directory Proxy Server should attempt to
   *                                 determine the limit based on its
   *                                 configuration.
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
  public ReloadGlobalIndexTask(@Nullable final String taskID,
              @NotNull final String baseDN,
              @Nullable final List<String> indexNames,
              @Nullable final Boolean reloadFromDS,
              @Nullable final Boolean reloadInBackground,
              @Nullable final Long maxEntriesPerSecond,
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
    super(taskID, RELOAD_GLOBAL_INDEX_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    Validator.ensureNotNull(baseDN);

    this.baseDN              = baseDN;
    this.reloadFromDS        = reloadFromDS;
    this.reloadInBackground  = reloadInBackground;
    this.maxEntriesPerSecond = maxEntriesPerSecond;

    if (indexNames == null)
    {
      this.indexNames = Collections.emptyList();
    }
    else
    {
      this.indexNames =
           Collections.unmodifiableList(new ArrayList<>(indexNames));
    }
  }



  /**
   * Creates a new reload global index task from the provided entry.
   *
   * @param  entry  The entry to use to create this reload global index task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a reload
   *                         global index task entry.
   */
  public ReloadGlobalIndexTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the base DN.  It must be present.
    baseDN = entry.getAttributeValue(ATTR_BASE_DN);
    if (baseDN == null)
    {
      throw new TaskException(
           ERR_RELOAD_GLOBAL_INDEX_MISSING_REQUIRED_ATTR.get(ATTR_BASE_DN));
    }

    // Get the names of the indexes to reload.  It may be empty or null.
    final String[] nameArray = entry.getAttributeValues(ATTR_INDEX_NAME);
    if ((nameArray == null) || (nameArray.length == 0))
    {
      indexNames = Collections.emptyList();
    }
    else
    {
      indexNames = Collections.unmodifiableList(Arrays.asList(nameArray));
    }

    // Get the flag indicating whether to reload from backend Directory Server
    // instances.
    reloadFromDS = entry.getAttributeValueAsBoolean(ATTR_RELOAD_FROM_DS);

    // Get the flag indicating whether to reload in a background thread.
    reloadInBackground =
         entry.getAttributeValueAsBoolean(ATTR_BACKGROUND_RELOAD);

    // Get the value specifying the maximum reload rate in entries per second.
    maxEntriesPerSecond =
         entry.getAttributeValueAsLong(ATTR_MAX_ENTRIES_PER_SECOND);
  }



  /**
   * Creates a new reload global index task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid reload global index task.
   */
  public ReloadGlobalIndexTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(RELOAD_GLOBAL_INDEX_TASK_CLASS, properties);

    final List<String> attrs = new ArrayList<>(10);
    Boolean background   = null;
    Boolean fromDS       = null;
    Long    maxPerSecond = null;
    String  baseDNStr    = null;

    for (final Map.Entry<TaskProperty,List<Object>> e : properties.entrySet())
    {
      final TaskProperty p = e.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = e.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BASE_DN))
      {
        baseDNStr = parseString(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INDEX_NAME))
      {
        final String[] nameArray = parseStrings(p, values, null);
        if (nameArray != null)
        {
          attrs.addAll(Arrays.asList(nameArray));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_RELOAD_FROM_DS))
      {
        fromDS = parseBoolean(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_BACKGROUND_RELOAD))
      {
        background = parseBoolean(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_MAX_ENTRIES_PER_SECOND))
      {
        maxPerSecond = parseLong(p, values, null);
      }
    }

    if (baseDNStr == null)
    {
      throw new TaskException(
           ERR_RELOAD_GLOBAL_INDEX_MISSING_REQUIRED_PROPERTY.get(ATTR_BASE_DN));
    }

    baseDN              = baseDNStr;
    indexNames          = Collections.unmodifiableList(attrs);
    reloadFromDS        = fromDS;
    reloadInBackground  = background;
    maxEntriesPerSecond = maxPerSecond;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_RELOAD_GLOBAL_INDEX.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_RELOAD_GLOBAL_INDEX.get();
  }



  /**
   * Retrieves the base DN of the entry-balancing request processor for which to
   * reload index data.
   *
   * @return  The base DN of the entry-balancing request processor for which to
   *          reload index data.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the names of the indexes to be reloaded.
   *
   * @return  The names of the indexes to be reloaded, or an empty list if the
   *          Directory Proxy Server should reload all indexes.
   */
  @NotNull()
  public List<String> getIndexNames()
  {
    return indexNames;
  }



  /**
   * Indicates whether to reload index information from backend Directory
   * Servers rather than a peer Directory Proxy Server.
   *
   * @return  {@code true} if the index information should be reloaded from
   *          backend Directory Servers, {@code false} if the index information
   *          should be reloaded from a peer Directory Proxy Server instance, or
   *          {@code null} if the Directory Proxy Server should automatically
   *          determine the reload data source.
   */
  @Nullable()
  public Boolean reloadFromDS()
  {
    return reloadFromDS;
  }



  /**
   * Indicates whether to perform the index reload processing in the background.
   *
   * @return  {@code true} if the index reload processing should be performed
   *          in the background (so that the task completes immediately),
   *          {@code false} if not, or {@code null} if the Directory Proxy
   *          Server should determine whether to perform the reload in the
   *          background.
   */
  @Nullable()
  public Boolean reloadInBackground()
  {
    return reloadInBackground;
  }



  /**
   * Retrieves the maximum reload rate in entries per second, if defined.
   *
   * @return  The maximum rate at which to reload index data, in entries per
   *          second, zero if no limit should be imposed, or {@code null} if the
   *          Directory Proxy Server should determine the maximum reload rate.
   */
  @Nullable()
  public Long getMaxEntriesPerSecond()
  {
    return maxEntriesPerSecond;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_RELOAD_GLOBAL_INDEX_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrList = new ArrayList<>(5);

    attrList.add(new Attribute(ATTR_BASE_DN, baseDN));

    if (! indexNames.isEmpty())
    {
      attrList.add(new Attribute(ATTR_INDEX_NAME, indexNames));
    }

    if (reloadFromDS != null)
    {
      attrList.add(new Attribute(ATTR_RELOAD_FROM_DS,
           String.valueOf(reloadFromDS)));
    }

    if (reloadInBackground != null)
    {
      attrList.add(new Attribute(ATTR_BACKGROUND_RELOAD,
           String.valueOf(reloadInBackground)));
    }

    if (maxEntriesPerSecond != null)
    {
      attrList.add(new Attribute(ATTR_MAX_ENTRIES_PER_SECOND,
           String.valueOf(maxEntriesPerSecond)));
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
         PROPERTY_BASE_DN,
         PROPERTY_INDEX_NAME,
         PROPERTY_RELOAD_FROM_DS,
         PROPERTY_BACKGROUND_RELOAD,
         PROPERTY_MAX_ENTRIES_PER_SECOND));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(15));

    props.put(PROPERTY_BASE_DN,
         Collections.<Object>singletonList(baseDN));
    props.put(PROPERTY_INDEX_NAME,
         Collections.<Object>unmodifiableList(indexNames));

    if (reloadFromDS == null)
    {
      props.put(PROPERTY_RELOAD_FROM_DS,
           Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_RELOAD_FROM_DS,
           Collections.<Object>singletonList(reloadFromDS));
    }

    if (reloadInBackground == null)
    {
      props.put(PROPERTY_BACKGROUND_RELOAD,
           Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_BACKGROUND_RELOAD,
           Collections.<Object>singletonList(reloadInBackground));
    }

    if (maxEntriesPerSecond == null)
    {
      props.put(PROPERTY_MAX_ENTRIES_PER_SECOND,
           Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_MAX_ENTRIES_PER_SECOND,
           Collections.<Object>singletonList(maxEntriesPerSecond));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
