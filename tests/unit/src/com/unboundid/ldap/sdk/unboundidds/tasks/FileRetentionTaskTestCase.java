/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the FileRetentionTask class.
 */
public class FileRetentionTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor that does not take any
   * arguments.
   */
  @Test()
  public void testDefaultConstructor()
  {
    final FileRetentionTask t = new FileRetentionTask();

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-file-retention"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior for a task instance that uses a retention count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetentionCount()
         throws Exception
  {
    FileRetentionTask t = new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);

    t = (FileRetentionTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new FileRetentionTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.FileRetentionTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTargetDirectory());
    assertEquals(t.getTargetDirectory(), "logs");

    assertNotNull(t.getFilenamePattern());
    assertEquals(t.getFilenamePattern(), "name-${timestamp}.log");

    assertNotNull(t.getTimestampFormat());
    assertEquals(t.getTimestampFormat(),
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS);

    assertNotNull(t.getRetainFileCount());
    assertEquals(t.getRetainFileCount(), Integer.valueOf(5));

    assertNull(t.getRetainFileAgeMillis());

    assertNull(t.getRetainAggregateFileSizeBytes());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-file-retention"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior for a task instance that uses a retention age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetentionAge()
         throws Exception
  {
    FileRetentionTask t = new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         null, 86_400_000L, null);

    t = (FileRetentionTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new FileRetentionTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.FileRetentionTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTargetDirectory());
    assertEquals(t.getTargetDirectory(), "logs");

    assertNotNull(t.getFilenamePattern());
    assertEquals(t.getFilenamePattern(), "name-${timestamp}.log");

    assertNotNull(t.getTimestampFormat());
    assertEquals(t.getTimestampFormat(),
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS);

    assertNull(t.getRetainFileCount());

    assertNotNull(t.getRetainFileAgeMillis());
    assertEquals(t.getRetainFileAgeMillis(), Long.valueOf(86_400_000L));

    assertNull(t.getRetainAggregateFileSizeBytes());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-file-retention"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior for a task instance that uses a retention size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetentionSize()
         throws Exception
  {
    FileRetentionTask t = new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         null, null, 100_000_000L);

    t = (FileRetentionTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new FileRetentionTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.FileRetentionTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTargetDirectory());
    assertEquals(t.getTargetDirectory(), "logs");

    assertNotNull(t.getFilenamePattern());
    assertEquals(t.getFilenamePattern(), "name-${timestamp}.log");

    assertNotNull(t.getTimestampFormat());
    assertEquals(t.getTimestampFormat(),
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS);

    assertNull(t.getRetainFileCount());

    assertNull(t.getRetainFileAgeMillis());

    assertNotNull(t.getRetainAggregateFileSizeBytes());
    assertEquals(t.getRetainAggregateFileSizeBytes(),
         Long.valueOf(100_000_000L));

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-file-retention"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior with a {@code null} target directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullTargetDirectory()
         throws Exception
  {
    new FileRetentionTask(null, "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);
  }



  /**
   * Tests the behavior with an empty target directory string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyTargetDirectoryString()
         throws Exception
  {
    new FileRetentionTask("", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);
  }



  /**
   * Tests the behavior with a {@code null} filename pattern.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullFilenamePattern()
         throws Exception
  {
    new FileRetentionTask("logs", null,
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);
  }



  /**
   * Tests the behavior with an empty filename pattern.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyFilenamePattern()
         throws Exception
  {
    new FileRetentionTask("logs", "",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);
  }



  /**
   * Tests the behavior with a {@code null} timestamp format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullTimestampFormat()
         throws Exception
  {
    new FileRetentionTask("logs", "name-${timestamp}.log", null, 5, null, null);
  }



  /**
   * Tests the behavior without any criteria.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNoCriteria()
         throws Exception
  {
    new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         null, null, null);
  }



  /**
   * Tests the behavior with a negative retain count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeRetainCount()
         throws Exception
  {
    new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         -1, null, null);
  }



  /**
   * Tests the behavior with a negative retain age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeRetainAge()
         throws Exception
  {
    new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         null, -1L, null);
  }



  /**
   * Tests the behavior with a negative retain size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNegativeRetainSize()
         throws Exception
  {
    new FileRetentionTask("logs", "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         null, null, -1L);
  }



  /**
   * Tests the behavior when trying to decode an entry that doesn't have the
   * required target directory attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithoutTargetDirectory()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that doesn't have the
   * required filename pattern attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithoutFilenamePattern()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that doesn't have the
   * required timestamp format attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithoutTimestampFormat()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has an invalid
   * timestamp format value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithInvalidTimestampFormat()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: invalid",
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that doesn't have any
   * retention criteria.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithoutAnyRetentionCriteria()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name()));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed
   * retain count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithMalformedRetainCount()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: malformed",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a negative
   * retain count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithNegativeRetainCount()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: -5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed
   * retain age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithMalformedRetainAge()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: malformed",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: 100000000"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed
   * retain size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithMalformedRetainSize()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: malformed"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a negative
   * retain size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodeEntryWithNegativeRetainSize()
         throws Exception
  {
    new FileRetentionTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-file-retention",
         "ds-task-id: test",
         "ds-task-class-name: " + FileRetentionTask.FILE_RETENTION_TASK_CLASS,
         "ds-task-file-retention-target-directory: logs",
         "ds-task-file-retention-filename-pattern: name-${timestamp}.log",
         "ds-task-file-retention-timestamp-format: " +
              FileRetentionTaskTimestampFormat.
                   GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
         "ds-task-file-retention-retain-file-count: 5",
         "ds-task-file-retention-retain-file-age: 1 week",
         "ds-task-file-retention-retain-aggregate-file-size-bytes: -1"));
  }



  /**
   * Tests the behavior when trying to decode a set of properties that doesn't
   * have the required target directory property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodePropertiesWithoutTargetDirectory()
         throws Exception
  {
    final FileRetentionTask t = new FileRetentionTask("logs",
         "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);

    final Map<TaskProperty,List<Object>> properties =
         new HashMap<>(t.getTaskPropertyValues());
    final Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         properties.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      if (e.getKey().getAttributeName().equalsIgnoreCase(
           "ds-task-file-retention-target-directory"))
      {
        iterator.remove();
        break;
      }
    }

    new FileRetentionTask(properties);
  }



  /**
   * Tests the behavior when trying to decode a set of properties that doesn't
   * have the required filename pattern property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodePropertiesWithoutFilenamePattern()
         throws Exception
  {
    final FileRetentionTask t = new FileRetentionTask("logs",
         "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);

    final Map<TaskProperty,List<Object>> properties =
         new HashMap<>(t.getTaskPropertyValues());
    final Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         properties.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      if (e.getKey().getAttributeName().equalsIgnoreCase(
           "ds-task-file-retention-filename-pattern"))
      {
        iterator.remove();
        break;
      }
    }

    new FileRetentionTask(properties);
  }



  /**
   * Tests the behavior when trying to decode a set of properties that doesn't
   * have the required timestamp format property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodePropertiesWithoutTimestampFormat()
         throws Exception
  {
    final FileRetentionTask t = new FileRetentionTask("logs",
         "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);

    final Map<TaskProperty,List<Object>> properties =
         new HashMap<>(t.getTaskPropertyValues());
    final Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         properties.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      if (e.getKey().getAttributeName().equalsIgnoreCase(
           "ds-task-file-retention-timestamp-format"))
      {
        iterator.remove();
        break;
      }
    }

    new FileRetentionTask(properties);
  }



  /**
   * Tests the behavior when trying to decode a set of properties that doesn't
   * have any retention criteria properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testDecodePropertiesWithoutRetentionCriteria()
         throws Exception
  {
    final FileRetentionTask t = new FileRetentionTask("logs",
         "name-${timestamp}.log",
         FileRetentionTaskTimestampFormat.
              GENERALIZED_TIME_UTC_WITH_MILLISECONDS,
         5, null, null);

    final Map<TaskProperty,List<Object>> properties =
         new HashMap<>(t.getTaskPropertyValues());
    final Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         properties.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      if (e.getKey().getAttributeName().equalsIgnoreCase(
           "ds-task-file-retention-retain-file-count"))
      {
        iterator.remove();
        break;
      }
    }

    new FileRetentionTask(properties);
  }
}
