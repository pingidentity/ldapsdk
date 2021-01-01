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



import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the remove attribute type task.
 */
public final class RemoveAttributeTypeTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that the generic task API includes information about the
   * remove attribute type task.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericTaskInteraction()
         throws Exception
  {
    assertNotNull(Task.getAvailableTaskTypes());
    assertFalse(Task.getAvailableTaskTypes().isEmpty());

    boolean found = false;
    for (final Task t : Task.getAvailableTaskTypes())
    {
      if (t instanceof RemoveAttributeTypeTask)
      {
        found = true;
      }
    }

    assertTrue(found);
  }



  /**
   * Tests the behavior for a task created from the default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultInstance()
         throws Exception
  {
    RemoveAttributeTypeTask t = new RemoveAttributeTypeTask("attrName");

    t = new RemoveAttributeTypeTask(
         new RemoveAttributeTypeTaskProperties(t));

    t = (RemoveAttributeTypeTask) Task.decodeTask(t.createTaskEntry());

    t = new RemoveAttributeTypeTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskName());
    assertFalse(t.getTaskName().isEmpty());

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());

    assertNotNull(t.getAttributeType());
    assertEquals(t.getAttributeType(), "attrName");

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains(
         "ds-task-remove-attribute-type"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());
    assertEquals(t.getAdditionalAttributes().size(), 1);
    assertEquals(t.getAdditionalAttributes().get(0).getName(),
         "ds-task-remove-attribute-type-attribute");

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.getTaskID());
    assertFalse(t.getTaskID().isEmpty());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.RemoveAttributeTypeTask");

    assertNotNull(t.getState());
    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNull(t.getScheduledStartTime());

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNotNull(t.getFailedDependencyAction());
    assertEquals(t.getFailedDependencyAction(), FailedDependencyAction.CANCEL);

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnStartAddresses());
    assertTrue(t.getNotifyOnStartAddresses().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnSuccessAddresses());
    assertTrue(t.getNotifyOnSuccessAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNull(t.getAlertOnStart());

    assertNull(t.getAlertOnSuccess());

    assertNull(t.getAlertOnError());

    assertNotNull(t.toString());
  }



  /**
   * Tests the behavior for a task created with a set of properties that have
   * values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromAllProperties()
         throws Exception
  {
    final RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");

    final Date d = new Date();

    p.setAttributeType("differentAttrName");
    p.setTaskID("123-456-7890");
    p.setScheduledStartTime(d);
    p.setDependencyIDs(Arrays.asList("d1", "d2", "d3"));
    p.setFailedDependencyAction(FailedDependencyAction.PROCESS);
    p.setNotifyOnStart(
         Arrays.asList("start1@example.com", "start2@example.com"));
    p.setNotifyOnCompletion(
         Arrays.asList("end1@example.com", "end2@example.com"));
    p.setNotifyOnSuccess(
         Arrays.asList("success1@example.com", "success2@example.com"));
    p.setNotifyOnError(
         Arrays.asList("error1@example.com", "error2@example.com"));
    p.setAlertOnStart(true);
    p.setAlertOnSuccess(false);
    p.setAlertOnError(true);


    RemoveAttributeTypeTask t = new RemoveAttributeTypeTask(p);

    t = new RemoveAttributeTypeTask(
         new RemoveAttributeTypeTaskProperties(t));

    t = (RemoveAttributeTypeTask) Task.decodeTask(t.createTaskEntry());

    t = new RemoveAttributeTypeTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskName());
    assertFalse(t.getTaskName().isEmpty());

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());

    assertNotNull(t.getAttributeType());
    assertEquals(t.getAttributeType(), "differentAttrName");

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains(
         "ds-task-remove-attribute-type"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "123-456-7890");

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.RemoveAttributeTypeTask");

    assertNotNull(t.getState());
    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNotNull(t.getScheduledStartTime());
    assertEquals(t.getScheduledStartTime(), d);

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertFalse(t.getDependencyIDs().isEmpty());
    assertEquals(t.getDependencyIDs(), Arrays.asList("d1", "d2", "d3"));

    assertNotNull(t.getFailedDependencyAction());
    assertEquals(t.getFailedDependencyAction(), FailedDependencyAction.PROCESS);

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnStartAddresses());
    assertFalse(t.getNotifyOnStartAddresses().isEmpty());
    assertEquals(t.getNotifyOnStartAddresses(),
         Arrays.asList("start1@example.com", "start2@example.com"));

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertFalse(t.getNotifyOnCompletionAddresses().isEmpty());
    assertEquals(t.getNotifyOnCompletionAddresses(),
         Arrays.asList("end1@example.com", "end2@example.com"));

    assertNotNull(t.getNotifyOnSuccessAddresses());
    assertFalse(t.getNotifyOnSuccessAddresses().isEmpty());
    assertEquals(t.getNotifyOnSuccessAddresses(),
         Arrays.asList("success1@example.com", "success2@example.com"));

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertFalse(t.getNotifyOnErrorAddresses().isEmpty());
    assertEquals(t.getNotifyOnErrorAddresses(),
         Arrays.asList("error1@example.com", "error2@example.com"));

    assertNotNull(t.getAlertOnStart());
    assertTrue(t.getAlertOnStart());

    assertNotNull(t.getAlertOnSuccess());
    assertFalse(t.getAlertOnSuccess());

    assertNotNull(t.getAlertOnError());
    assertTrue(t.getAlertOnError());

    assertNotNull(t.toString());
  }



  /**
   * Tests the behavior when trying to create a remove attribute type task from
   * an entry that does not specify the attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testEntryMalformedLogDuration()
         throws Exception
  {
    new RemoveAttributeTypeTask(new Entry(
         "dn: ds-task-id=123-456-7890,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-remove-attribute-type",
         "ds-task-id: 123-456-7890",
         "ds-task-class-name: com.unboundid.directory.server.tasks." +
              "RemoveAttributeTypeTask"));
  }



  /**
   * Tests the behavior when trying to create a remove attribute type task from
   * a properties map that does not include the attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testPropertiesMissingAttributeType()
         throws Exception
  {
    new RemoveAttributeTypeTask(
         Collections.<TaskProperty,List<Object>>emptyMap());
  }
}
