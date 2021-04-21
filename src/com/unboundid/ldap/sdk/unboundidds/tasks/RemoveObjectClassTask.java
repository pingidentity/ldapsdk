/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to safely remove
 * an object class from the server schema.  It will make sure that the object
 * class is not in use in the server before removing it.
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
 *   <LI>The name or OID of the object class to remove from the server
 *       schema.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RemoveObjectClassTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the remove
   * object class task.
   */
  @NotNull static final String REMOVE_OBJECT_CLASS_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RemoveObjectClassTask";



  /**
   * The name of the attribute used to specify the name or OID of the object
   * class to remove from the server schema.
   */
  @NotNull public static final String ATTR_OBJECT_CLASS =
       "ds-task-remove-object-class-name";



  /**
   * The name of the object class used in remove object class task entries.
   */
  @NotNull public static final String OC_REMOVE_OBJECT_CLASS_TASK =
       "ds-task-remove-object-class";



  /**
   * The task property that will be used for the object class name or OID.
   */
  @NotNull static final TaskProperty PROPERTY_OBJECT_CLASS =
     new TaskProperty(ATTR_OBJECT_CLASS,
          INFO_REMOVE_OC_DISPLAY_NAME_ATTRIBUTE_TYPE.get(),
          INFO_REMOVE_OC_DESCRIPTION_ATTRIBUTE_TYPE.get(),
          String.class, true, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 457552922409235779L;



  // The name or OID for the object class to remove.
  @NotNull private final String objectClass;



  /**
   * Creates a new uninitialized remove object class task instance that should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  RemoveObjectClassTask()
  {
    super();

    objectClass = null;
  }



  /**
   * Creates a new remove object class task instance that will remove the
   * specified object class from the server schema and will use the default
   * values for all other properties.
   *
   * @param  objectClass  The name or OID of the object class to remove from the
   *                      server schema.
   */
  public RemoveObjectClassTask(@NotNull final String objectClass)
  {
    this(new RemoveObjectClassTaskProperties(objectClass));
  }



  /**
   * Creates a new remove object class task instance using the provided
   * properties.
   *
   * @param  properties  The properties to use to create the remove object class
   *                     task.  It must not be {@code null}.
   */
  public RemoveObjectClassTask(
              @NotNull final RemoveObjectClassTaskProperties properties)
  {
    super(properties.getTaskID(), REMOVE_OBJECT_CLASS_TASK_CLASS,
         properties.getScheduledStartTime(), properties.getDependencyIDs(),
         properties.getFailedDependencyAction(), properties.getNotifyOnStart(),
         properties.getNotifyOnCompletion(), properties.getNotifyOnSuccess(),
         properties.getNotifyOnError(), properties.getAlertOnStart(),
         properties.getAlertOnSuccess(), properties.getAlertOnError());

    objectClass = properties.getObjectClass();
  }



  /**
   * Creates a new remove object class task from the provided entry.
   *
   * @param  entry  The entry to use to create this remove object class task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a remove
   *                         object class task entry.
   */
  public RemoveObjectClassTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    objectClass = entry.getAttributeValue(ATTR_OBJECT_CLASS);
    if (objectClass == null)
    {
      throw new TaskException(ERR_REMOVE_OC_ENTRY_MISSING_OC.get(entry.getDN(),
           ATTR_OBJECT_CLASS));
    }
  }



  /**
   * Creates a new remove object class task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid remove object class task.
   */
  public RemoveObjectClassTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(REMOVE_OBJECT_CLASS_TASK_CLASS, properties);

    String oc = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = StaticUtils.toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();

      if (attrName.equals(ATTR_OBJECT_CLASS))
      {
        oc = parseString(p, values, oc);
      }
    }

    objectClass = oc;
    if (objectClass == null)
    {
      throw new TaskException(ERR_REMOVE_OC_PROPS_MISSING_OC.get(
           ATTR_OBJECT_CLASS));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_REMOVE_OC_TASK_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_REMOVE_OC_TASK_DESCRIPTION.get();
  }



  /**
   * Retrieves the name or OID of the object class to remove from the server
   * schema.
   *
   * @return  The name or OID of the object class to remove from the server
   *          schema.
   */
  @NotNull()
  public String getObjectClass()
  {
    return objectClass;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_REMOVE_OBJECT_CLASS_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    return Collections.singletonList(
         new Attribute(ATTR_OBJECT_CLASS, objectClass));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.singletonList(PROPERTY_OBJECT_CLASS);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final Map<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));
    props.put(PROPERTY_OBJECT_CLASS,
         Collections.<Object>singletonList(objectClass));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
