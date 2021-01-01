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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the Task class.
 */
public class TaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with both a task ID and a task class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithTaskID()
         throws Exception
  {
    Task t = new Task("test-task-id", "bogus.task.class.name");
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "test-task-id");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=test-task-id,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "bogus.task.class.name");

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

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }


  /**
   * Tests the first constructor without a task ID but with a task class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoTaskID()
         throws Exception
  {
    Task t = new Task(null, "bogus.task.class.name");
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=" + t.getTaskID() +
                             ",cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "bogus.task.class.name");

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

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }


  /**
   * Tests the first constructor without a task class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoTaskClass()
         throws Exception
  {
    new Task(null, (String) null);
  }



  /**
   * Tests the second constructor with non-{@code null} but empty lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithEmptyLists()
         throws Exception
  {
    Date d = new Date();

    Task t = new Task("test-task-id", "bogus.task.class.name", d,
                      Collections.<String>emptyList(),
                      FailedDependencyAction.DISABLE,
                      Collections.<String>emptyList(),
                      Collections.<String>emptyList());
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "test-task-id");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=test-task-id,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "bogus.task.class.name");

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

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }



  /**
   * Tests the second constructor with non-empty lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithNonEmptyLists()
         throws Exception
  {
    Date d = new Date();

    List<String> dependencyIDs = Arrays.asList("dependency1", "dependency2");

    List<String> notifyOnStart=
         Arrays.asList("start-address-1@example.com");

    List<String> notifyOnCompletion =
         Arrays.asList("completion-address-1@example.com",
                       "completion-address-2@example.com");

    List<String> notifyOnSuccess =
         Arrays.asList("success-address-1@example.com",
                       "success-address-2@example.com",
                       "success-address-3@example.com");

    List<String> notifyOnError =
         Arrays.asList("error-address-1@example.com",
                       "error-address-2@example.com",
                       "error-address-3@example.com",
                       "error-address-4@example.com");


    Task t = new Task("test-task-id", "bogus.task.class.name", d, dependencyIDs,
                      FailedDependencyAction.CANCEL, notifyOnStart,
                      notifyOnCompletion, notifyOnSuccess, notifyOnError,
                      true, false, null);
    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "test-task-id");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=test-task-id,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "bogus.task.class.name");

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

    assertNotNull(t.getNotifyOnStartAddresses());
    assertEquals(t.getNotifyOnStartAddresses().size(), 1);
    assertEquals(t.getNotifyOnStartAddresses(), notifyOnStart);

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertEquals(t.getNotifyOnCompletionAddresses().size(), 2);
    assertEquals(t.getNotifyOnCompletionAddresses(), notifyOnCompletion);

    assertNotNull(t.getNotifyOnSuccessAddresses());
    assertEquals(t.getNotifyOnSuccessAddresses().size(), 3);
    assertEquals(t.getNotifyOnSuccessAddresses(), notifyOnSuccess);

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertEquals(t.getNotifyOnErrorAddresses().size(), 4);
    assertEquals(t.getNotifyOnErrorAddresses(), notifyOnError);

    assertNotNull(t.getAlertOnStart());
    assertEquals(t.getAlertOnStart(), Boolean.TRUE);

    assertNotNull(t.getAlertOnSuccess());
    assertEquals(t.getAlertOnSuccess(), Boolean.FALSE);

    assertNull(t.getAlertOnError());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }



  /**
   * Tests the third constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor3Valid(final Entry e)
         throws Exception
  {
    Task t = new Task(e);

    assertNotNull(t);

    assertNotNull(t.getTaskEntry());
    assertEquals(t.getTaskEntry(), e);

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN(e.getDN()));

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskClassName());

    assertNotNull(t.getState());

    assertNotNull(t.getDependencyIDs());

    assertNotNull(t.getLogMessages());

    assertNotNull(t.getNotifyOnStartAddresses());

    assertNotNull(t.getNotifyOnCompletionAddresses());

    assertNotNull(t.getNotifyOnSuccessAddresses());

    assertNotNull(t.getNotifyOnErrorAddresses());

    t.getAlertOnStart();

    t.getAlertOnSuccess();

    t.getAlertOnError();

    assertNotNull(t.getAdditionalObjectClasses());

    assertNotNull(t.getAdditionalAttributes());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));

    assertNotNull(t.toString());
  }



  /**
   * Retrieves a set of entries that may be parsed as valid task definitions.
   *
   * @return  A set of entries that may be parsed as valid task definitions.
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
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-scheduled-start-time: 20080101000000Z",
                  "ds-task-actual-start-time: 20080101000000Z",
                  "ds-task-completion-time: 20080101010101Z",
                  "ds-task-dependency-id: validTask1",
                  "ds-task-failed-dependency-action: cancel",
                  "ds-task-log-message: [01/Jan/2008:00:00:00 +0000] starting",
                  "ds-task-log-message: [01/Jan/2008:01:01:01 +0000] done",
                  "ds-task-notify-on-start: janine@example.com",
                  "ds-task-notify-on-completion: ray@example.com",
                  "ds-task-notify-on-completion: winston@example.com",
                  "ds-task-notify-on-success: dana@example.com",
                  "ds-task-notify-on-success: louis@example.com",
                  "ds-task-notify-on-error: peter@example.com",
                  "ds-task-notify-on-error: egon@example.com",
                  "ds-task-alert-on-start: true",
                  "ds-task-alert-on-success: true",
                  "ds-task-alert-on-error: true")
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
    new Task(e);
  }



  /**
   * Tests the decodeTask method with an invalid test entry.
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
   * Retrieves a set of entries that cannot be parsed as valid task definitions.
   *
   * @return  A set of entries that cannot be parsed as valid task definitions.
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
        new Entry("dn: ds-task-id=bad oc,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: not-ds-task",
                  "ds-task-id: bad oc",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: cn=no id,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "cn: no id",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no class,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: no class",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=bad state,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: bad state",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: bad")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=bad scheduled start time," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: bad scheduled start time",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-scheduled-start-time: bad")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=bad actual start time," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: bad actual start time",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-actual-start-time: bad")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=bad completion time," +
                       "cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "ds-task-id: bad completion time",
                  "ds-task-class-name: test.class.name",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-completion-time: bad")
      }
    };
  }



  /**
   * Tests the fourth constructor with a property map containing all values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4All()
         throws Exception
  {
    List<Object> taskID = Arrays.<Object>asList("taskID");
    List<Object> scheduledStartTime = Arrays.<Object>asList(new Date());
    List<Object> depIDs = Arrays.<Object>asList("a", "b");
    List<Object> failedDepAction = Arrays.<Object>asList("disable");
    List<Object> notifyOnStart = Arrays.<Object>asList("a@b.com");
    List<Object> notifyOnCompletion = Arrays.<Object>asList("c@d.com");
    List<Object> notifyOnSuccess = Arrays.<Object>asList("e@f.com");
    List<Object> notifyOnError = Arrays.<Object>asList("g@h.com");
    Boolean alertOnStart = false;
    Boolean alertOnSuccess = true;
    Boolean alertOnError = false;

    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    for (TaskProperty p : Task.getCommonTaskProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-dependency-id"))
      {
        properties.put(p, depIDs);
      }
      else if (name.equals("ds-task-failed-dependency-action"))
      {
        properties.put(p, failedDepAction);
      }
      else if (name.equals("ds-task-notify-on-start"))
      {
        properties.put(p, notifyOnStart);
      }
      else if (name.equals("ds-task-notify-on-completion"))
      {
        properties.put(p, notifyOnCompletion);
      }
      else if (name.equals("ds-task-notify-on-success"))
      {
        properties.put(p, notifyOnSuccess);
      }
      else if (name.equals("ds-task-notify-on-error"))
      {
        properties.put(p, notifyOnError);
      }
      else if (name.equals("ds-task-alert-on-start"))
      {
        properties.put(p, Collections.<Object>singletonList(alertOnStart));
      }
      else if (name.equals("ds-task-alert-on-success"))
      {
        properties.put(p, Collections.<Object>singletonList(alertOnSuccess));
      }
      else if (name.equals("ds-task-alert-on-error"))
      {
        properties.put(p, Collections.<Object>singletonList(alertOnError));
      }
      else if (name.equals("ds-task-scheduled-start-time"))
      {
        properties.put(p, scheduledStartTime);
      }
      else if (name.equals("ds-task-id"))
      {
        properties.put(p, taskID);
      }
    }

    Task t = new Task("task.class.name", properties);

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "taskID");

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=taskID,cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "task.class.name");

    assertEquals(t.getState(), TaskState.UNSCHEDULED);

    assertTrue(t.isPending());

    assertFalse(t.isRunning());

    assertFalse(t.isCompleted());

    assertNotNull(t.getScheduledStartTime());
    assertEquals(t.getScheduledStartTime(), scheduledStartTime.get(0));

    assertNull(t.getActualStartTime());

    assertNull(t.getCompletionTime());

    assertNotNull(t.getDependencyIDs());
    assertEquals(t.getDependencyIDs().size(), 2);

    assertNotNull(t.getFailedDependencyAction());
    assertEquals(t.getFailedDependencyAction(), FailedDependencyAction.DISABLE);

    assertNotNull(t.getLogMessages());
    assertTrue(t.getLogMessages().isEmpty());

    assertNotNull(t.getNotifyOnStartAddresses());
    assertEquals(t.getNotifyOnStartAddresses().size(), 1);

    assertNotNull(t.getNotifyOnCompletionAddresses());
    assertEquals(t.getNotifyOnCompletionAddresses().size(), 1);

    assertNotNull(t.getNotifyOnSuccessAddresses());
    assertEquals(t.getNotifyOnSuccessAddresses().size(), 1);

    assertNotNull(t.getNotifyOnErrorAddresses());
    assertEquals(t.getNotifyOnErrorAddresses().size(), 1);

    assertNotNull(t.getAlertOnStart());
    assertEquals(t.getAlertOnStart(), Boolean.FALSE);

    assertNotNull(t.getAlertOnSuccess());
    assertEquals(t.getAlertOnSuccess(), Boolean.TRUE);

    assertNotNull(t.getAlertOnError());
    assertEquals(t.getAlertOnError(), Boolean.FALSE);

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }



  /**
   * Tests the fourth constructor with a property map containing no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4None()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    Task t = new Task("task.class.name", properties);

    assertNotNull(t);

    assertNull(t.getTaskEntry());

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN("ds-task-id=" + t.getTaskID() +
                             ",cn=Scheduled Tasks,cn=tasks"));

    assertEquals(t.getTaskClassName(), "task.class.name");

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
    assertEquals(t.getFailedDependencyAction(),
                 FailedDependencyAction.CANCEL);

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

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.toString());
  }



  /**
   * Tests the {@code parseBooleanValue} method when the target attribute is not
   * present in the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseBooleanValueMissing()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time");

    assertTrue(Task.parseBooleanValue(e, "ds-task-boolean-value", true));
    assertFalse(Task.parseBooleanValue(e, "ds-task-boolean-value", false));
  }



  /**
   * Tests the {@code parseBooleanValue} method when the target attribute is
   * present in the entry with a value of "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseBooleanValueTrue()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time",
                        "ds-task-boolean-value: true");

    assertTrue(Task.parseBooleanValue(e, "ds-task-boolean-value", true));
    assertTrue(Task.parseBooleanValue(e, "ds-task-boolean-value", false));
  }



  /**
   * Tests the {@code parseBooleanValue} method when the target attribute is
   * present in the entry with a value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseBooleanValueFalse()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time",
                        "ds-task-boolean-value: false");

    assertFalse(Task.parseBooleanValue(e, "ds-task-boolean-value", true));
    assertFalse(Task.parseBooleanValue(e, "ds-task-boolean-value", false));
  }



  /**
   * Tests the {@code parseBooleanValue} method when the target attribute is
   * present in the entry with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testParseBooleanValueInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time",
                        "ds-task-boolean-value: invalid");

    Task.parseBooleanValue(e, "ds-task-boolean-value", true);
  }



  /**
   * Tests the {@code parseStringList} method when the target attribute is not
   * present in the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseStringListMissing()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time");

    assertNotNull(Task.parseStringList(e, "ds-task-string-list"));
    assertTrue(Task.parseStringList(e, "ds-task-string-list").isEmpty());
  }



  /**
   * Tests the {@code parseStringList} method when the target attribute is
   * present in the entry with a single value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseStringListSingleValue()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time",
                        "ds-task-string-list: value1");

    assertNotNull(Task.parseStringList(e, "ds-task-string-list"));
    assertEquals(Task.parseStringList(e, "ds-task-string-list").size(), 1);
  }



  /**
   * Tests the {@code parseStringList} method when the target attribute is
   * present in the entry with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseStringListMultipleValues()
         throws Exception
  {
    Entry e = new Entry("dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
                        "objectClass: top",
                        "objectclass: ds-task",
                        "ds-task-id: test",
                        "ds-task-class-name: test.class.name",
                        "ds-task-state: waiting_on_start_time",
                        "ds-task-string-list: value1",
                        "ds-task-string-list: value2",
                        "ds-task-string-list: value3");

    assertNotNull(Task.parseStringList(e, "ds-task-string-list"));
    assertEquals(Task.parseStringList(e, "ds-task-string-list").size(), 3);
  }



  /**
   * Tests the {@code getAvailableTaskTypes} method to retrieve the set of
   * supported types, and uses those types to test the {@code getTaskName},
   * {@code getTaskDescription}, {@code getCommonTaskProperties}, and
   * {@code getTaskSpecificProperties} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAvailableTaskTypes()
         throws Exception
  {
    List<Task> taskTypes = Task.getAvailableTaskTypes();

    assertNotNull(taskTypes);
    assertFalse(taskTypes.isEmpty());

    for (Task t : taskTypes)
    {
      assertNotNull(t);

      assertNotNull(t.getTaskName());

      assertNotNull(t.getTaskDescription());

      assertNotNull(Task.getCommonTaskProperties());
      assertFalse(Task.getCommonTaskProperties().isEmpty());

      assertNotNull(t.getTaskSpecificProperties());
    }
  }



  /**
   * Tests the {@code getTaskName} method for generic tasks.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGenericTaskName()
         throws Exception
  {
    Task t = new Task();
    assertNotNull(t.getTaskName());
  }



  /**
   * Tests the {@code getTaskDescription} method for generic tasks.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGenericTaskDescription()
         throws Exception
  {
    Task t = new Task();
    assertNotNull(t.getTaskDescription());
  }



  /**
   * Tests the {@code parseBoolean} method with a valid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   * @param  expectedValue  The expected value for the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validParseBoolean")
  public void testParseBooleanValid(TaskProperty p, List<Object> values,
                                    Boolean defaultValue, Boolean expectedValue)
         throws Exception
  {
    assertEquals(Task.parseBoolean(p, values, defaultValue),
                 expectedValue);
  }



  /**
   * Retrieves a set of test data that can be parsed as valid Boolean data.
   *
   * @return  A set of test data that can be parsed as valid Boolean data.
   */
  @DataProvider(name = "validParseBoolean")
  public Object[][] getValidParseBooleanData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Boolean.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Boolean.class, true, false, false);


    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.TRUE),
        Boolean.TRUE,
        Boolean.TRUE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.FALSE),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.FALSE),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("true"),
        Boolean.TRUE,
        Boolean.TRUE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("false"),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("FaLsE"),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        Boolean.TRUE,
        Boolean.TRUE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Boolean.TRUE),
        Boolean.TRUE,
        Boolean.TRUE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Boolean.FALSE),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Boolean.FALSE),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("true"),
        Boolean.TRUE,
        Boolean.TRUE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("false"),
        Boolean.TRUE,
        Boolean.FALSE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("FaLsE"),
        Boolean.TRUE,
        Boolean.FALSE
      }
    };
  }



  /**
   * Tests the {@code parseBoolean} method with an invalid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidParseBoolean",
        expectedExceptions = { TaskException.class })
  public void testParseBooleanInvalid(TaskProperty p, List<Object> values,
                                      Boolean defaultValue)
         throws Exception
  {
    Task.parseBoolean(p, values, defaultValue);
  }



  /**
   * Retrieves a set of test data that cannot be parsed as valid Boolean data.
   *
   * @return  A set of test data that cannot be parsed as valid Boolean data.
   */
  @DataProvider(name = "invalidParseBoolean")
  public Object[][] getInvalidParseBooleanData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Boolean.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Boolean.class, true, false, false);


    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.TRUE, Boolean.FALSE),
        Boolean.TRUE
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Long.valueOf(5)),
        Boolean.TRUE
      },


      new Object[]
      {
        pN,
        Arrays.<Object>asList("invalid"),
        Boolean.TRUE
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(),
        Boolean.TRUE
      }
    };
  }



  /**
   * Tests the {@code parseDate} method with a valid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   * @param  expectedValue  The expected value for the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validParseDate")
  public void testParseDateValid(TaskProperty p, List<Object> values,
                                 Date defaultValue, Date expectedValue)
         throws Exception
  {
    assertEquals(Task.parseDate(p, values, defaultValue),
                 expectedValue);
  }



  /**
   * Retrieves a set of test data that can be parsed as valid Date data.
   *
   * @return  A set of test data that can be parsed as valid Date data.
   */
  @DataProvider(name = "validParseDate")
  public Object[][] getValidParseDateData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, true, false, false);

    Date d   = new Date();
    String s = encodeGeneralizedTime(d);

    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, true, false, false,
                                       new Object[] { d });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(d),
        d,
        d
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(d),
        null,
        d
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(s),
        d,
        d
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(s),
        null,
        d
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        d,
        d
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(d),
        d,
        d
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(d),
        null,
        d
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(s),
        d,
        d
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(s),
        null,
        d
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList(s),
        null,
        d
      },
    };
  }



  /**
   * Tests the {@code parseDate} method with an invalid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidParseDate",
        expectedExceptions = { TaskException.class })
  public void testParseDateInvalid(TaskProperty p, List<Object> values,
                                   Date defaultValue)
         throws Exception
  {
    Task.parseDate(p, values, defaultValue);
  }



  /**
   * Retrieves a set of test data that cannot be parsed as valid Date data.
   *
   * @return  A set of test data that cannot be parsed as valid Date data.
   */
  @DataProvider(name = "invalidParseDate")
  public Object[][] getInvalidParseDateData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, true, false, false);

    Date d1 = new Date();
    Date d2 = new Date(d1.getTime() + 1234);

    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, true, false, false,
                                       new Object[] { d1, d2 });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(d1, d2),
        d1
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Long.valueOf(5)),
        d1
      },


      new Object[]
      {
        pN,
        Arrays.<Object>asList("invalid"),
        d1
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(),
        d1
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("20080101010101Z"),
        d1
      },
    };
  }



  /**
   * Tests the {@code parseLong} method with a valid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   * @param  expectedValue  The expected value for the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validParseLong")
  public void testParseLongValid(TaskProperty p, List<Object> values,
                                 Long defaultValue, Long expectedValue)
         throws Exception
  {
    assertEquals(Task.parseLong(p, values, defaultValue),
                 expectedValue);
  }



  /**
   * Retrieves a set of test data that can be parsed as valid Long data.
   *
   * @return  A set of test data that can be parsed as valid Long data.
   */
  @DataProvider(name = "validParseLong")
  public Object[][] getValidParseLongData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Long.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Long.class, true, false, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       Long.class, true, false, false,
                                       new Object[] { Long.valueOf(0),
                                                      Long.valueOf(5) });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(Long.valueOf(5)),
        Long.valueOf(0),
        Long.valueOf(5)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Long.valueOf(3)),
        null,
        Long.valueOf(3)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Integer.valueOf(15)),
        Long.valueOf(0),
        Long.valueOf(15)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Double.valueOf(45)),
        null,
        Long.valueOf(45)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("2"),
        Long.valueOf(0),
        Long.valueOf(2)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("7"),
        null,
        Long.valueOf(7)
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        Long.valueOf(9),
        Long.valueOf(9)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Long.valueOf(5)),
        Long.valueOf(0),
        Long.valueOf(5)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Long.valueOf(3)),
        null,
        Long.valueOf(3)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Integer.valueOf(15)),
        Long.valueOf(0),
        Long.valueOf(15)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(Double.valueOf(45)),
        null,
        Long.valueOf(45)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("2"),
        Long.valueOf(0),
        Long.valueOf(2)
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("7"),
        null,
        Long.valueOf(7)
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList(Long.valueOf(5)),
        null,
        Long.valueOf(5)
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("0"),
        null,
        Long.valueOf(0)
      },
    };
  }



  /**
   * Tests the {@code parseLong} method with an invalid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidParseLong",
        expectedExceptions = { TaskException.class })
  public void testParseLongInvalid(TaskProperty p, List<Object> values,
                                   Long defaultValue)
         throws Exception
  {
    Task.parseLong(p, values, defaultValue);
  }



  /**
   * Retrieves a set of test data that cannot be parsed as valid Long data.
   *
   * @return  A set of test data that cannot be parsed as valid Long data.
   */
  @DataProvider(name = "invalidParseLong")
  public Object[][] getInvalidParseLongData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       Date.class, true, false, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       Long.class, true, false, false,
                                       new Object[] { Long.valueOf(0),
                                                      Long.valueOf(5) });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(Long.valueOf(1), Long.valueOf(2)),
        null,
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.TRUE),
        Long.valueOf(7)
      },


      new Object[]
      {
        pN,
        Arrays.<Object>asList("invalid"),
        null
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(),
        null
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList(Long.valueOf(1)),
        null
      },
    };
  }



  /**
   * Tests the {@code parseString} method with a valid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   * @param  expectedValue  The expected value for the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validParseString")
  public void testParseValidString(TaskProperty p, List<Object> values,
                                  String defaultValue, String expectedValue)
         throws Exception
  {
    assertEquals(Task.parseString(p, values, defaultValue),
                 expectedValue);
  }



  /**
   * Retrieves a set of test data that can be parsed as valid String data.
   *
   * @return  A set of test data that can be parsed as valid String data.
   */
  @DataProvider(name = "validParseString")
  public Object[][] getValidParseStringData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       String.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false,
                                       new Object[] { "foo", "bar" });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList("a"),
        "b",
        "a"
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("c"),
        null,
        "c"
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(new StringBuilder("d")),
        "e",
        "d"
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        "f",
        "f"
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("a"),
        "b",
        "a"
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("c"),
        null,
        "c"
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(new StringBuilder("d")),
        "e",
        "d"
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("foo"),
        null,
        "foo"
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList(new StringBuilder("bar")),
        "foo",
        "bar"
      },
    };
  }



  /**
   * Tests the {@code parseString} method with an invalid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValue   The default value to use if none is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidParseString",
        expectedExceptions = { TaskException.class })
  public void testParseStringInvalid(TaskProperty p, List<Object> values,
                                     String defaultValue)
         throws Exception
  {
    Task.parseString(p, values, defaultValue);
  }



  /**
   * Retrieves a set of test data that cannot be parsed as valid String data.
   *
   * @return  A set of test data that cannot be parsed as valid String data.
   */
  @DataProvider(name = "invalidParseString")
  public Object[][] getInvalidParseStringData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       String.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false,
                                       new Object[] { "foo", "bar" });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList("foo", "bar"),
        null,
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.TRUE),
        "foo"
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(),
        null
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("baz"),
        null
      },
    };
  }



  /**
   * Tests the {@code parseString} method with a valid value.
   *
   * @param  p               The property with which the values are associated.
   * @param  values          The set of values for the property.
   * @param  defaultValues   The default values to use if none is provided.
   * @param  expectedValues  The expected values for the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validParseStrings")
  public void testParseValidStrings(TaskProperty p, List<Object> values,
                                   String[] defaultValues,
                                   String expectedValues[])
         throws Exception
  {
    String[] parsedValues = Task.parseStrings(p, values, defaultValues);
    assertTrue(Arrays.equals(parsedValues, expectedValues));
  }



  /**
   * Retrieves a set of test data that can be parsed as valid String array data.
   *
   * @return  A set of test data that can be parsed as valid String array data.
   */
  @DataProvider(name = "validParseStrings")
  public Object[][] getValidParseStringsData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       String.class, false, true, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, true, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, true, false,
                                       new Object[] { "foo", "bar" });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList("a"),
        new String[] { "b" },
        new String[] { "a" }
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList("c", new StringBuilder("d")),
        new String[] { "e", "f", "g" },
        new String[] { "c", "d" }
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        new String[] {  },
        new String[] {  }
      },

      new Object[]
      {
        pN,
        Arrays.<Object>asList(),
        new String[] { "h", "i" },
        new String[] { "h", "i" }
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("j"),
        new String[] { "k" },
        new String[] { "j" }
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList("l", new StringBuilder("m")),
        new String[] { "n", "o", "p" },
        new String[] { "l", "m" }
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("foo"),
        new String[] { "foo" },
        new String[] { "foo" }
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("foo", new StringBuilder("bar")),
        new String[] { "foo" },
        new String[] { "foo", "bar" }
      },
    };
  }



  /**
   * Tests the {@code parseStrings} method with an invalid value.
   *
   * @param  p              The property with which the values are associated.
   * @param  values         The set of values for the property.
   * @param  defaultValues  The default values to use if none is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidParseStrings",
        expectedExceptions = { TaskException.class })
  public void testParseStringsInvalid(TaskProperty p, List<Object> values,
                                      String[] defaultValues)
         throws Exception
  {
    Task.parseStrings(p, values, defaultValues);
  }



  /**
   * Retrieves a set of test data that cannot be parsed as valid String array
   * data.
   *
   * @return  A set of test data that cannot be parsed as valid String array
   *          data.
   */
  @DataProvider(name = "invalidParseStrings")
  public Object[][] getInvalidParseStringsData()
  {
    TaskProperty pN = new TaskProperty("attrName", "displayName", "description",
                                       String.class, false, false, false);
    TaskProperty pR = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false);
    TaskProperty pA = new TaskProperty("attrName", "displayName", "description",
                                       String.class, true, false, false,
                                       new Object[] { "foo", "bar" });

    return new Object[][]
    {
      new Object[]
      {
        pN,
        Arrays.<Object>asList(Boolean.TRUE),
        new String[] { "foo" }
      },

      new Object[]
      {
        pR,
        Arrays.<Object>asList(),
        null
      },

      new Object[]
      {
        pA,
        Arrays.<Object>asList("baz"),
        null
      },
    };
  }
}
