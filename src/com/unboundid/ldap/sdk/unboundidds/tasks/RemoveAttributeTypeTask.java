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
 * an attribute type from the server schema.  It will make sure that the
 * attribute type is not in use in the server before removing it.
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
 *   <LI>The name or OID of the attribute type to remove from the server
 *       schema.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RemoveAttributeTypeTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the remove
   * attribute type task.
   */
  @NotNull static final String REMOVE_ATTRIBUTE_TYPE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RemoveAttributeTypeTask";



  /**
   * The name of the attribute used to specify the name or OID of the attribute
   * type to remove from the server schema.
   */
  @NotNull public static final String ATTR_ATTRIBUTE_TYPE =
       "ds-task-remove-attribute-type-attribute";



  /**
   * The name of the object class used in remove attribute type task entries.
   */
  @NotNull public static final String OC_REMOVE_ATTRIBUTE_TYPE_TASK =
       "ds-task-remove-attribute-type";



  /**
   * The task property that will be used for the attribute type name or OID.
   */
  @NotNull static final TaskProperty PROPERTY_ATTRIBUTE_TYPE =
     new TaskProperty(ATTR_ATTRIBUTE_TYPE,
          INFO_REMOVE_ATTR_TYPE_DISPLAY_NAME_ATTRIBUTE_TYPE.get(),
          INFO_REMOVE_ATTR_TYPE_DESCRIPTION_ATTRIBUTE_TYPE.get(),
          String.class, true, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3118507632013307187L;



  // The name or OID for the attribute type to remove.
  @NotNull private final String attributeType;



  /**
   * Creates a new uninitialized remove attribute type task instance that should
   * only be used for obtaining general information about this task, including
   * the task name, description, and supported properties.  Attempts to use a
   * task created with this constructor for any other reason will likely fail.
   */
  RemoveAttributeTypeTask()
  {
    super();

    attributeType = null;
  }



  /**
   * Creates a new remove attribute type task instance that will remove the
   * specified attribute type from the server schema and will use the default
   * values for all other properties.
   *
   * @param  attributeType  The name or OID of the attribute type to remove from
   *                        the server schema.
   */
  public RemoveAttributeTypeTask(@NotNull final String attributeType)
  {
    this(new RemoveAttributeTypeTaskProperties(attributeType));
  }



  /**
   * Creates a new remove attribute type task instance using the provided
   * properties.
   *
   * @param  properties  The properties to use to create the remove attribute
   *                     type task.  It must not be {@code null}.
   */
  public RemoveAttributeTypeTask(
              @NotNull final RemoveAttributeTypeTaskProperties properties)
  {
    super(properties.getTaskID(), REMOVE_ATTRIBUTE_TYPE_TASK_CLASS,
         properties.getScheduledStartTime(), properties.getDependencyIDs(),
         properties.getFailedDependencyAction(), properties.getNotifyOnStart(),
         properties.getNotifyOnCompletion(), properties.getNotifyOnSuccess(),
         properties.getNotifyOnError(), properties.getAlertOnStart(),
         properties.getAlertOnSuccess(), properties.getAlertOnError());

    attributeType = properties.getAttributeType();
  }



  /**
   * Creates a new remove attribute type task from the provided entry.
   *
   * @param  entry  The entry to use to create this remove attribute type task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a remove
   *                         attribute tyep task entry.
   */
  public RemoveAttributeTypeTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    attributeType = entry.getAttributeValue(ATTR_ATTRIBUTE_TYPE);
    if (attributeType == null)
    {
      throw new TaskException(ERR_REMOVE_ATTR_TYPE_ENTRY_MISSING_ATTR_TYPE.get(
           entry.getDN(), ATTR_ATTRIBUTE_TYPE));
    }
  }



  /**
   * Creates a new remove attribute type task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid remove attribute type task.
   */
  public RemoveAttributeTypeTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(REMOVE_ATTRIBUTE_TYPE_TASK_CLASS, properties);

    String attrType = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = StaticUtils.toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();

      if (attrName.equals(ATTR_ATTRIBUTE_TYPE))
      {
        attrType = parseString(p, values, attrType);
      }
    }

    attributeType = attrType;
    if (attributeType == null)
    {
      throw new TaskException(ERR_REMOVE_ATTR_TYPE_PROPS_MISSING_ATTR_TYPE.get(
           ATTR_ATTRIBUTE_TYPE));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_REMOVE_ATTR_TYPE_TASK_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_REMOVE_ATTR_TYPE_TASK_DESCRIPTION.get();
  }



  /**
   * Retrieves the name or OID of the attribute type to remove from the server
   * schema.
   *
   * @return  The name or OID of the attribute type to remove from the server
   *          schema.
   */
  @NotNull()
  public String getAttributeType()
  {
    return attributeType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_REMOVE_ATTRIBUTE_TYPE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    return Collections.singletonList(
         new Attribute(ATTR_ATTRIBUTE_TYPE, attributeType));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.singletonList(PROPERTY_ATTRIBUTE_TYPE);
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
    props.put(PROPERTY_ATTRIBUTE_TYPE,
         Collections.<Object>singletonList(attributeType));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
