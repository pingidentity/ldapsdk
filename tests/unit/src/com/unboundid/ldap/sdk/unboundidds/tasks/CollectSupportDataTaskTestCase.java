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

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the collect support data task.
 */
public final class CollectSupportDataTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that the generic task API includes information about the
   * collect support data task.
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
      if (t instanceof CollectSupportDataTask)
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
    CollectSupportDataTask t = new CollectSupportDataTask();

    t = new CollectSupportDataTask(
         new CollectSupportDataTaskProperties(t));

    t = (CollectSupportDataTask) Task.decodeTask(t.createTaskEntry());

    t = new CollectSupportDataTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskName());
    assertFalse(t.getTaskName().isEmpty());

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());

    assertNull(t.getOutputPath());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getIncludeExpensiveData());

    assertNull(t.getIncludeReplicationStateDump());

    assertNull(t.getIncludeBinaryFiles());

    assertNull(t.getIncludeExtensionSource());

    assertNull(t.getUseSequentialMode());

    assertNull(t.getSecurityLevel());

    assertNull(t.getReportCount());

    assertNull(t.getReportIntervalSeconds());

    assertNull(t.getJStackCount());

    assertNull(t.getLogDuration());

    assertNull(t.getLogDurationMillis());

    assertNull(t.getLogFileHeadCollectionSizeKB());

    assertNull(t.getLogFileTailCollectionSizeKB());

    assertNull(t.getComment());

    assertNull(t.getRetainPreviousSupportDataArchiveCount());

    assertNull(t.getRetainPreviousSupportDataArchiveAge());

    assertNull(t.getRetainPreviousSupportDataArchiveAgeMillis());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains(
         "ds-task-collect-support-data"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(t.getTaskID());
    assertFalse(t.getTaskID().isEmpty());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.CollectSupportDataTask");

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
    final CollectSupportDataTaskProperties p =
         new CollectSupportDataTaskProperties();

    final Date d = new Date();

    p.setOutputPath("/tmp/output-path");
    p.setEncryptionPassphraseFile("/tmp/pw.txt");
    p.setIncludeExpensiveData(true);
    p.setIncludeReplicationStateDump(false);
    p.setIncludeBinaryFiles(true);
    p.setIncludeExtensionSource(false);
    p.setUseSequentialMode(true);
    p.setSecurityLevel(CollectSupportDataSecurityLevel.MAXIMUM);
    p.setReportCount(2);
    p.setReportIntervalSeconds(3);
    p.setJStackCount(4);
    p.setLogDuration("5 minutes");
    p.setLogFileHeadCollectionSizeKB(123);
    p.setLogFileTailCollectionSizeKB(456);
    p.setComment("foo");
    p.setRetainPreviousSupportDataArchiveCount(5);
    p.setRetainPreviousSupportDataArchiveAge("1 week");
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


    CollectSupportDataTask t = new CollectSupportDataTask(p);

    t = new CollectSupportDataTask(
         new CollectSupportDataTaskProperties(t));

    t = (CollectSupportDataTask) Task.decodeTask(t.createTaskEntry());

    t = new CollectSupportDataTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskName());
    assertFalse(t.getTaskName().isEmpty());

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());

    assertNotNull(t.getOutputPath());
    assertEquals(t.getOutputPath(), "/tmp/output-path");

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "/tmp/pw.txt");

    assertNotNull(t.getIncludeExpensiveData());
    assertTrue(t.getIncludeExpensiveData());

    assertNotNull(t.getIncludeReplicationStateDump());
    assertFalse(t.getIncludeReplicationStateDump());

    assertNotNull(t.getIncludeBinaryFiles());
    assertTrue(t.getIncludeBinaryFiles());

    assertNotNull(t.getIncludeExtensionSource());
    assertFalse(t.getIncludeExtensionSource());

    assertNotNull(t.getUseSequentialMode());
    assertTrue(t.getUseSequentialMode());

    assertNotNull(t.getSecurityLevel());
    assertEquals(t.getSecurityLevel(),
         CollectSupportDataSecurityLevel.MAXIMUM);

    assertNotNull(t.getReportCount());
    assertEquals(t.getReportCount().intValue(), 2);

    assertNotNull(t.getReportIntervalSeconds());
    assertEquals(t.getReportIntervalSeconds().intValue(), 3);

    assertNotNull(t.getJStackCount());
    assertEquals(t.getJStackCount().intValue(), 4);

    assertNotNull(t.getLogDuration());
    assertEquals(t.getLogDuration(), "5 minutes");

    assertNotNull(t.getLogDurationMillis());
    assertEquals(t.getLogDurationMillis().longValue(), 300_000L);

    assertNotNull(t.getLogFileHeadCollectionSizeKB());
    assertEquals(t.getLogFileHeadCollectionSizeKB().intValue(), 123);

    assertNotNull(t.getLogFileTailCollectionSizeKB());
    assertEquals(t.getLogFileTailCollectionSizeKB().intValue(), 456);

    assertNotNull(t.getComment());
    assertEquals(t.getComment(), "foo");

    assertNotNull(t.getRetainPreviousSupportDataArchiveCount());
    assertEquals(t.getRetainPreviousSupportDataArchiveCount().intValue(), 5);

    assertNotNull(t.getRetainPreviousSupportDataArchiveAge());
    assertEquals(t.getRetainPreviousSupportDataArchiveAge(), "1 week");

    assertNotNull(t.getRetainPreviousSupportDataArchiveAgeMillis());
    assertEquals(t.getRetainPreviousSupportDataArchiveAgeMillis().longValue(),
         604_800_000L);

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains(
         "ds-task-collect-support-data"));

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
         "com.unboundid.directory.server.tasks.CollectSupportDataTask");

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
   * Tests the behavior of the {@code getSecurityLevelName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSecurityLevelName()
         throws Exception
  {
    assertNull(CollectSupportDataTask.getSecurityLevelName(null));

    for (final CollectSupportDataSecurityLevel l :
         CollectSupportDataSecurityLevel.values())
    {
      assertEquals(CollectSupportDataTask.getSecurityLevelName(l), l.getName());
    }
  }



  /**
   * Tests the behavior of the {@code getIntegerAsLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIntegerAsLong()
         throws Exception
  {
    assertNull(CollectSupportDataTask.getIntegerAsLong(null));

    assertEquals(CollectSupportDataTask.getIntegerAsLong(12345),
         Long.valueOf(12345L));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * an entry with a malformed security level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testEntryMalformedSecurityLevel()
         throws Exception
  {
    new CollectSupportDataTask(new Entry(
         "dn: ds-task-id=123-456-7890,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-collect-support-data",
         "ds-task-id: 123-456-7890",
         "ds-task-class-name: com.unboundid.directory.server.tasks." +
              "CollectSupportDataTask",
         "ds-task-collect-support-data-security-level: malformed"));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * an entry with a malformed log duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testEntryMalformedLogDuration()
         throws Exception
  {
    new CollectSupportDataTask(new Entry(
         "dn: ds-task-id=123-456-7890,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-collect-support-data",
         "ds-task-id: 123-456-7890",
         "ds-task-class-name: com.unboundid.directory.server.tasks." +
              "CollectSupportDataTask",
         "ds-task-collect-support-data-log-duration: malformed"));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * an entry with a malformed retain age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testEntryMalformedRetainAge()
         throws Exception
  {
    new CollectSupportDataTask(new Entry(
         "dn: ds-task-id=123-456-7890,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-collect-support-data",
         "ds-task-id: 123-456-7890",
         "ds-task-class-name: com.unboundid.directory.server.tasks." +
              "CollectSupportDataTask",
         "ds-task-collect-support-data-retain-previous-support-data-" +
              "archive-age: malformed"));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * a properties map that contains a malformed security level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testPropertiesMalformedSecurityLevel()
         throws Exception
  {
    new CollectSupportDataTask(StaticUtils.mapOf(
         CollectSupportDataTask.PROPERTY_SECURITY_LEVEL,
         Collections.<Object>singletonList("malformed")));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * a properties map that contains a malformed log duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testPropertiesMalformedLogDuration()
         throws Exception
  {
    new CollectSupportDataTask(StaticUtils.mapOf(
         CollectSupportDataTask.PROPERTY_LOG_DURATION,
         Collections.<Object>singletonList("malformed")));
  }



  /**
   * Tests the behavior when trying to create a collect support data task from
   * a properties map that contains a malformed retain age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testPropertiesMalformedRetainAge()
         throws Exception
  {
    new CollectSupportDataTask(StaticUtils.mapOf(
         CollectSupportDataTask.PROPERTY_RETAIN_PREVIOUS_ARCHIVE_AGE,
         Collections.<Object>singletonList("malformed")));
  }
}
