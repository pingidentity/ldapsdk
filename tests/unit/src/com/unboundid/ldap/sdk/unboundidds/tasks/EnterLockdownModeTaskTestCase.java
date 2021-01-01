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



import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the EnterLockdownModeTask class.
 */
public class EnterLockdownModeTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithTaskID()
         throws Exception
  {
    EnterLockdownModeTask t = new EnterLockdownModeTask("foo");

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "foo");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=foo,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNull(t.getReason());

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNull(t.getScheduledStartTime());

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNull(t.getFailedDependencyAction());

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor without a task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoTaskID()
         throws Exception
  {
    EnterLockdownModeTask t = new EnterLockdownModeTask((String) null);

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=" + t.getTaskID() +
                             ",cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNull(t.getReason());

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNull(t.getScheduledStartTime());

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNull(t.getFailedDependencyAction());

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with a non-{@code null} task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithTaskID()
         throws Exception
  {
    EnterLockdownModeTask t = new EnterLockdownModeTask("foo", "bar");

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "foo");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=foo,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNotNull(t.getReason());
    assertEquals(t.getReason(), "bar");

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNull(t.getScheduledStartTime());

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNull(t.getFailedDependencyAction());

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor without a task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoTaskID()
         throws Exception
  {
    EnterLockdownModeTask t = new EnterLockdownModeTask(null, "bar");

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=" + t.getTaskID() +
                             ",cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNotNull(t.getReason());
    assertEquals(t.getReason(), "bar");

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNull(t.getScheduledStartTime());

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNull(t.getFailedDependencyAction());

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the third constructor with non-{@code null} but empty lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithEmptyLists()
         throws Exception
  {
    Date d = new Date();

    EnterLockdownModeTask t =
         new EnterLockdownModeTask("foo", d, Collections.<String>emptyList(),
                                   FailedDependencyAction.DISABLE,
                                   Collections.<String>emptyList(),
                                   Collections.<String>emptyList());
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "foo");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=foo,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNull(t.getReason());

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNotNull(t.getScheduledStartTime());
    assertEquals(t.getScheduledStartTime(), d);

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertTrue(t.getDependencyIDs().isEmpty());

    assertNotNull(t.getFailedDependencyAction());
    assertEquals(t.getFailedDependencyAction(),
                 FailedDependencyAction.DISABLE);

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertTrue(t.getNotifyOnCompletionAddresses().isEmpty());

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertTrue(t.getNotifyOnErrorAddresses().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the fourth constructor with non-empty lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4WithNonEmptyLists()
         throws Exception
  {
    Date d = new Date();

    List<String> dependencyIDs = Arrays.asList("dependency1", "dependency2");

    List<String> notifyOnCompletion =
         Arrays.asList("junior-admin-1@example.com",
                       "junior-admin-2@example.com",
                       "junior-admin-3@example.com");

    List<String> notifyOnError =
         Arrays.asList("senior-admin-1@example.com",
                       "senior-admin-2@example.com",
                       "senior-admin-3@example.com",
                       "senior-admin-4@example.com");


    EnterLockdownModeTask t =
         new EnterLockdownModeTask("foo", "bar", d, dependencyIDs,
                                   FailedDependencyAction.CANCEL,
                                   notifyOnCompletion, notifyOnError);
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "foo");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=foo,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.EnterLockdownModeTask");

    assertNotNull(t.getReason());
    assertEquals(t.getReason(), "bar");

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNotNull(t.getScheduledStartTime());
    assertEquals(t.getScheduledStartTime(), d);

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertEquals(t.getDependencyIDs().size(), 2);

    assertNotNull(t.getFailedDependencyAction());
    assertEquals(t.getFailedDependencyAction(),
                 FailedDependencyAction.CANCEL);

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertEquals(t.getNotifyOnCompletionAddresses().size(), 3);

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertEquals(t.getNotifyOnErrorAddresses().size(), 4);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the fifth constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor5Valid(final Entry e)
         throws Exception
  {
    EnterLockdownModeTask t = new EnterLockdownModeTask(e);

    assertNotNull(t);

    assertNotNull(t.getTaskEntry());
    assertEquals(t.getTaskEntry(), e);

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN(e.getDN()));

    t.getReason();

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskClassName());

    assertNotNull(t.getState());

    assertNotNull(t.getDependencyIDs());

    assertNotNull(t.getLogMessages());

    assertNotNull(t.getNotifyOnCompletionAddresses());

    assertNotNull(t.getNotifyOnErrorAddresses());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                      "ds-task-enter-lockdown-mode");

    assertNotNull(t.getAdditionalAttributes());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof EnterLockdownModeTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid enter lockdown mode
   * task definitions.
   *
   * @return  A set of entries that may be parsed as valid enter lockdown mode
   *          task definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "validEntries")
  public Object[][] getValidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=validTask1,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "EnterLockdownModeTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-enter-lockdown-mode",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "EnterLockdownModeTask",
                  "ds-task-enter-lockdown-reason: bar",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-scheduled-start-time: 20080101000000Z",
                  "ds-task-actual-start-time: 20080101000000Z",
                  "ds-task-completion-time: 20080101010101Z",
                  "ds-task-dependency-id: validTask1",
                  "ds-task-failed-dependency-action: cancel",
                  "ds-task-log-message: [01/Jan/2008:00:00:00 +0000] starting",
                  "ds-task-log-message: [01/Jan/2008:01:01:01 +0000] done",
                  "ds-task-notify-on-completion: ray@example.com",
                  "ds-task-notify-on-completion: winston@example.com",
                  "ds-task-notify-on-error: peter@example.com",
                  "ds-task-notify-on-error: egon@example.com")
      }
    };
  }



  /**
   * Tests the third constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testConstructor3Invalid(final Entry e)
         throws Exception
  {
    new EnterLockdownModeTask(e);
  }



  /**
   * Tests the decodeTask constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testDecodeTask(final Entry e)
         throws Exception
  {
    Task.decodeTask(e);
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid enter lockdown
   * mode task definitions.
   *
   * @return  A set of entries that cannot be parsed as valid enter lockdown
   *          mode task definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "invalidEntries")
  public Object[][] getInvalidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=fails in superclass,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: not-ds-task",
                  "ds-task-id: fails in superclass",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "EnterLockdownModeTask",
                  "ds-task-state: waiting_on_start_time")
      }
    };
  }



  /**
   * Tests the fourth constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4Empty()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p :
         new EnterLockdownModeTask().getTaskSpecificProperties())
    {
      properties.put(p, Arrays.<Object>asList("foo"));
    }

    EnterLockdownModeTask t = new EnterLockdownModeTask(properties);

    Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (TaskProperty p : Task.getCommonTaskProperties())
    {
      if (props.get(p) == null)
      {
        continue;
      }

      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (TaskProperty p : t.getTaskSpecificProperties())
    {
      assertNotNull(props.get(p));
      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }
}
