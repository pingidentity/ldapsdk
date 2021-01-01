/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to populate the
 * values of a composed attribute in existing entries without the need to export
 * the data to LDIF and re-import it.
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
 *   <LI>The names or DNs of the configuration entries for the composed
 *       attribute plugin instances for which to generate values.</LI>
 *   <LI>The backend IDs of the backends in which the values are to be
 *       composed.</LI>
 *   <LI>The maximum number of entries to update per second.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PopulateComposedAttributeValuesTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the populate
   * composed attribute values task.
   */
  @NotNull static final String POPULATE_COMPOSED_ATTRIBUTE_VALUES_TASK_CLASS =
       "com.unboundid.directory.server.tasks." +
            "PopulateComposedAttributeValuesTask";



  /**
   * The name of the attribute used to specify the backned IDs of the backends
   * in which composed values are to be generated.
   */
  @NotNull private static final String ATTR_BACKEND_ID =
       "ds-task-populate-composed-attribute-backend-id";



  /**
   * The name of the attribute used to specify the maximum number of entries to
   * update per second.
   */
  @NotNull private static final String ATTR_MAX_RATE_PER_SECOND =
       "ds-task-populate-composed-attribute-max-rate-per-second";



  /**
   * The name of the attribute used to specify the names or DNs of the
   * configuration entries for the composed attribute plugin instances for which
   * to generate values.
   */
  @NotNull private static final String ATTR_PLUGIN_CONFIG =
       "ds-task-populate-composed-attribute-plugin-config";



  /**
   * The name of the object class used in populate composed attribute value task
   * entries.
   */
  @NotNull private static final String
       OC_POPULATE_COMPOSED_ATTRIBUTE_VALUES_TASK =
            "ds-task-populate-composed-attribute";



  /**
   * The task property that will be used for the backend IDs for the backends in
   * which to generate values.
   */
  @NotNull private static final TaskProperty PROPERTY_BACKEND_ID =
     new TaskProperty(ATTR_BACKEND_ID,
          INFO_POPULATE_COMPOSED_ATTR_DISPLAY_NAME_BACKEND_ID.get(),
          INFO_POPULATE_COMPOSED_ATTR_DESCRIPTION_BACKEND_ID.get(),
          String.class, false, true, false);



  /**
   * The task property that will be used for the max rate per second.
   */
  @NotNull private static final TaskProperty PROPERTY_MAX_RATE_PER_SECOND =
     new TaskProperty(ATTR_MAX_RATE_PER_SECOND,
          INFO_POPULATE_COMPOSED_ATTR_DISPLAY_NAME_MAX_RATE.get(),
          INFO_POPULATE_COMPOSED_ATTR_DESCRIPTION_MAX_RATE.get(), Long.class,
          false, false, false);



  /**
   * The task property that will be used for the names or DNs for the composed
   * attribute plugins for which to generate values.
   */
  @NotNull private static final TaskProperty PROPERTY_PLUGIN_CONFIG =
     new TaskProperty(ATTR_PLUGIN_CONFIG,
          INFO_POPULATE_COMPOSED_ATTR_DISPLAY_NAME_PLUGIN_CONFIG.get(),
          INFO_POPULATE_COMPOSED_ATTR_DESCRIPTION_PLUGIN_CONFIG.get(),
          String.class, false, true, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5225591249266743619L;



  // The maximum number of entries to update per second.
  @Nullable private final Integer maxRatePerSecond;

  // The names of the backend IDs for the backends in which to generate values.
  @NotNull private final List<String> backendIDs;

  // The names or DNs of the configuration entries for the composed attribute
  // plugins for which to generate values.
  @NotNull private final List<String> pluginConfigs;



  /**
   * Creates a new uninitialized populate composed attribute values task
   * instance that should only be used for obtaining general information about
   * this task, including the task name, description, and supported properties.
   * Attempts to use a task created with this constructor for any other reason
   * will likely fail.
   */
  public PopulateComposedAttributeValuesTask()
  {
    super();

    maxRatePerSecond = null;
    backendIDs = null;
    pluginConfigs = null;
  }



  /**
   * Creates a new populate composed attribute values task with the provided
   * information.
   *
   * @param  taskID            The task ID to use for this task.  If it is
   *                           {@code null} then a UUID will be generated for
   *                           use as the task ID.
   * @param  pluginConfigs     The names or DNs of the configuration entries for
   *                           the composed attribute plugin instances to use to
   *                           generate values.  If this is not specified, then
   *                           values will be generated for all enabled composed
   *                           attribute plugin instances defined in the
   *                           configuration.
   * @param  backendIDs        The backend IDs for the backends in which
   *                           composed values will be generated.  If this is
   *                           not specified, then an appropriate set of
   *                           backends will be determined from the
   *                           configurations of the selected plugin instances.
   * @param  maxRatePerSecond  The maximum number of entries to update per
   *                           second.  If this is not specified, then no rate
   *                           limit will be imposed.
   */
  public PopulateComposedAttributeValuesTask(@Nullable final String taskID,
              @Nullable final List<String> pluginConfigs,
              @Nullable final List<String> backendIDs,
              @Nullable final Integer maxRatePerSecond)
  {
    this(taskID, pluginConfigs, backendIDs, maxRatePerSecond, null, null, null,
         null, null, null, null, null, null, null);
  }



  /**
   * Creates a new populate composed attribute values task with the provided
   * information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  pluginConfigs           The names or DNs of the configuration
   *                                 entries for the composed attribute plugin
   *                                 instances to use to generate values.  If
   *                                 this is not specified, then values will be
   *                                 generated for all enabled composed
   *                                 attribute plugin instances defined in the
   *                                 configuration.
   * @param  backendIDs              The backend IDs for the backends in which
   *                                 composed values will be generated.  If this
   *                                 is not specified, then an appropriate set
   *                                 of backends will be determined from the
   *                                 configurations of the selected plugin
   *                                 instances.
   * @param  maxRatePerSecond        The maximum number of entries to update per
   *                                 second.  If this is not specified, then no
   *                                 rate limit will be imposed.
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
  public PopulateComposedAttributeValuesTask(@Nullable final String taskID,
              @Nullable final List<String> pluginConfigs,
              @Nullable final List<String> backendIDs,
              @Nullable final Integer maxRatePerSecond,
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
    super(taskID, POPULATE_COMPOSED_ATTRIBUTE_VALUES_TASK_CLASS,
         scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnStart, notifyOnCompletion, notifyOnSuccess, notifyOnError,
         alertOnStart, alertOnSuccess, alertOnError);

    if (pluginConfigs == null)
    {
      this.pluginConfigs = Collections.emptyList();
    }
    else
    {
      this.pluginConfigs =
           Collections.unmodifiableList(new ArrayList<>(pluginConfigs));
    }

    if (backendIDs == null)
    {
      this.backendIDs = Collections.emptyList();
    }
    else
    {
      this.backendIDs =
           Collections.unmodifiableList(new ArrayList<>(backendIDs));
    }

    this.maxRatePerSecond = maxRatePerSecond;
  }



  /**
   * Creates a new populate composed attribute values task from the provided
   * entry.
   *
   * @param  entry  The entry to use to create this populate composed attribute
   *                values task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         populate composed attribute values task entry.
   */
  public PopulateComposedAttributeValuesTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the set of plugin configurations.
    final String[] configs = entry.getAttributeValues(ATTR_PLUGIN_CONFIG);
    if ((configs == null) || (configs.length == 0))
    {
      this.pluginConfigs = Collections.emptyList();
    }
    else
    {
      this.pluginConfigs = Collections.unmodifiableList(Arrays.asList(configs));
    }


    // Get the set of backend IDs.
    final String[] ids = entry.getAttributeValues(ATTR_BACKEND_ID);
    if ((ids == null) || (ids.length == 0))
    {
      this.backendIDs = Collections.emptyList();
    }
    else
    {
      this.backendIDs = Collections.unmodifiableList(Arrays.asList(ids));
    }


    // Get the max rate per second.
    maxRatePerSecond =
         entry.getAttributeValueAsInteger(ATTR_MAX_RATE_PER_SECOND);
  }



  /**
   * Creates a populate composed attribute values task from the provided set of
   * task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid populate composed attribute values
   *                         task.
   */
  public PopulateComposedAttributeValuesTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(POPULATE_COMPOSED_ATTRIBUTE_VALUES_TASK_CLASS, properties);

    Integer maxRate = null;
    final List<String> configs = new ArrayList<>();
    final List<String> ids = new ArrayList<>();
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_PLUGIN_CONFIG))
      {
        final String[] parsedConfigs =
             parseStrings(p, values, StaticUtils.NO_STRINGS);
        if ((parsedConfigs != null) && (parsedConfigs.length > 0))
        {
          configs.addAll(Arrays.asList(parsedConfigs));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_BACKEND_ID))
      {
        final String[] parsedIDs =
             parseStrings(p, values, StaticUtils.NO_STRINGS);
        if ((parsedIDs != null) && (parsedIDs.length > 0))
        {
          ids.addAll(Arrays.asList(parsedIDs));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_MAX_RATE_PER_SECOND))
      {
        final Long l = parseLong(p, values, null);
        if (l != null)
        {
          maxRate = l.intValue();
        }
      }
    }

    pluginConfigs = Collections.unmodifiableList(configs);
    backendIDs = Collections.unmodifiableList(ids);
    maxRatePerSecond = maxRate;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_POPULATE_COMPOSED_ATTR_VALUES.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_POPULATE_COMPOSED_ATTR_VALUES.get();
  }



  /**
   * Retrieves a list of the names or DNs of the configuration entries for the
   * composed attribute plugin instances for which to generate values.
   *
   * @return  A list of the names or DNs of the configuration entries for the
   *          composed attribute plugin instances for which to generate values,
   *          or an empty list if the server should generate composed values for
   *          all enabled composed attribute plugin instances defined in the
   *          configuration.
   */
  @NotNull()
  public List<String> getPluginConfigs()
  {
    return pluginConfigs;
  }



  /**
   * Retrieves a list of the backend IDs for the backends in which to generate
   * composed values.
   *
   * @return  A list of the backend IDs for the backends in which to generate
   *          composed values, or an empty list if the server should determine
   *          an appropriate set of backends from the configurations of the
   *          selected plugin instances.
   */
  @NotNull()
  public List<String> getBackendIDs()
  {
    return backendIDs;
  }



  /**
   * Retrieves the maximum number of entries per second for which composed
   * values should be generated.
   *
   * @return  The maximum number of entries per second for which composed values
   *          should be generated, or {@code null} if no rate limit should be
   *          imposed.
   */
  @Nullable()
  public Integer getMaxRatePerSecond()
  {
    return maxRatePerSecond;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(
         OC_POPULATE_COMPOSED_ATTRIBUTE_VALUES_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final List<Attribute> attrList = new ArrayList<>(3);

    if (! pluginConfigs.isEmpty())
    {
      attrList.add(new Attribute(ATTR_PLUGIN_CONFIG, pluginConfigs));
    }

    if (! backendIDs.isEmpty())
    {
      attrList.add(new Attribute(ATTR_BACKEND_ID, backendIDs));
    }

    if (maxRatePerSecond != null)
    {
      attrList.add(new Attribute(ATTR_MAX_RATE_PER_SECOND,
           String.valueOf(maxRatePerSecond)));
    }

    return Collections.unmodifiableList(attrList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(
         PROPERTY_PLUGIN_CONFIG,
         PROPERTY_BACKEND_ID,
         PROPERTY_MAX_RATE_PER_SECOND));
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

    props.put(PROPERTY_PLUGIN_CONFIG,
         Collections.<Object>unmodifiableList(pluginConfigs));
    props.put(PROPERTY_BACKEND_ID,
         Collections.<Object>unmodifiableList(backendIDs));

    if (maxRatePerSecond != null)
    {
      props.put(PROPERTY_MAX_RATE_PER_SECOND,
           Collections.<Object>singletonList(maxRatePerSecond.longValue()));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
