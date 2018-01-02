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
 * This class defines a Directory Server task that can be used to add the
 * contents of one or more files to the server schema.
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
 *   <LI>The names of the files to add to the server schema.  The specified
 *       files must exist within the server's schema configuration directory
 *       with the appropriate schema elements defined.  They should be only the
 *       base names for the file and should not include any path
 *       information.  At least one name must be provided.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AddSchemaFileTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the add schema
   * file task.
   */
  static final String ADD_SCHEMA_FILE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.AddSchemaFileTask";



  /**
   * The name of the attribute used to specify the name(s) of the schema file(s)
   * to add.
   */
  private static final String ATTR_SCHEMA_FILE =
       "ds-task-schema-file-name";



  /**
   * The name of the object class used in add schema file task entries.
   */
  private static final String OC_ADD_SCHEMA_FILE_TASK =
       "ds-task-add-schema-file";



  /**
   * The task property that will be used for the schema file names.
   */
  private static final TaskProperty PROPERTY_SCHEMA_FILE =
     new TaskProperty(ATTR_SCHEMA_FILE, INFO_DISPLAY_NAME_SCHEMA_FILE.get(),
                      INFO_DESCRIPTION_SCHEMA_FILE.get(), String.class, true,
                      true, false);




  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5430392768265418966L;



  // The names of the schema files to be added.
  private final List<String> schemaFileNames;



  /**
   * Creates a new uninitialized add schema file task instance which should only
   * be used for obtaining general information about this task, including the
   * task name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public AddSchemaFileTask()
  {
    schemaFileNames = null;
  }




  /**
   * Creates a new add schema file task to add the specified file to the server
   * schema.
   *
   * @param  taskID          The task ID to use for this task.  If it is
   *                         {@code null} then a UUID will be generated for use
   *                         as the task ID.
   * @param  schemaFileName  The name (without path information) of the file to
   *                         add to the server schema.  It must not be
   *                         {@code null}.
   */
  public AddSchemaFileTask(final String taskID, final String schemaFileName)
  {
    this(taskID, Arrays.asList(schemaFileName), null, null, null, null, null);

    ensureNotNull(schemaFileName);
  }




  /**
   * Creates a new add schema file task to add the specified files to the server
   * schema.
   *
   * @param  taskID           The task ID to use for this task.  If it is
   *                          {@code null} then a UUID will be generated for use
   *                          as the task ID.
   * @param  schemaFileNames  The list of names (without path information) of
   *                          the files to add to the server schema.  It must
   *                          not be {@code null} or empty.
   */
  public AddSchemaFileTask(final String taskID,
                           final List<String> schemaFileNames)
  {
    this(taskID, schemaFileNames, null, null, null, null, null);
  }



  /**
   * Creates a new add schema file task to add the specified files to the server
   * schema.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  schemaFileNames         The list of names (without path
   *                                 information) of the files to add to the
   *                                 server schema.  It must not be {@code null}
   *                                 or empty.
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
  public AddSchemaFileTask(final String taskID,
                           final List<String> schemaFileNames,
                           final Date scheduledStartTime,
                           final List<String> dependencyIDs,
                           final FailedDependencyAction failedDependencyAction,
                           final List<String> notifyOnCompletion,
                           final List<String> notifyOnError)
  {
    super(taskID, ADD_SCHEMA_FILE_TASK_CLASS, scheduledStartTime,
          dependencyIDs, failedDependencyAction, notifyOnCompletion,
          notifyOnError);

    ensureNotNull(schemaFileNames);
    ensureFalse(schemaFileNames.isEmpty(),
                "AddSchemaFileTask.schemaFileNames must not be empty.");

    this.schemaFileNames = Collections.unmodifiableList(schemaFileNames);
  }



  /**
   * Creates a new add schema file task from the provided entry.
   *
   * @param  entry  The entry to use to create this add schema file task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         add schema file task entry.
   */
  public AddSchemaFileTask(final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the set of schema file names.  It must be present.
    final String[] fileNames = entry.getAttributeValues(ATTR_SCHEMA_FILE);
    if ((fileNames == null) || (fileNames.length == 0))
    {
      throw new TaskException(ERR_ADD_SCHEMA_FILE_TASK_NO_FILES.get(
                                   getTaskEntryDN()));
    }

    schemaFileNames = Collections.unmodifiableList(Arrays.asList(fileNames));
  }



  /**
   * Creates a new add schema file task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid add schema file task.
   */
  public AddSchemaFileTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(ADD_SCHEMA_FILE_TASK_CLASS, properties);

    String[] names = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_SCHEMA_FILE))
      {
        names = parseStrings(p, values, names);
      }
    }

    if (names == null)
    {
      throw new TaskException(ERR_ADD_SCHEMA_FILE_TASK_NO_FILES.get(
                                   getTaskEntryDN()));
    }

    schemaFileNames = Collections.unmodifiableList(Arrays.asList(names));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_ADD_SCHEMA_FILE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_ADD_SCHEMA_FILE.get();
  }



  /**
   * Retrieves the names (without path information) of the schema files to be
   * added to the server.
   *
   * @return  The names of the schema files to be added to the server.
   */
  public List<String> getSchemaFileNames()
  {
    return schemaFileNames;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_ADD_SCHEMA_FILE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    return Arrays.asList(new Attribute(ATTR_SCHEMA_FILE, schemaFileNames));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(PROPERTY_SCHEMA_FILE));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>();

    props.put(PROPERTY_SCHEMA_FILE,
              Collections.<Object>unmodifiableList(schemaFileNames));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
