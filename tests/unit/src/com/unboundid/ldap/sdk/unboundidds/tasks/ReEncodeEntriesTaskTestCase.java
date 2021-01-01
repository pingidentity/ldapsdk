/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.LinkedHashMap;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the re-encode entries task.
 */
public final class ReEncodeEntriesTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the re-encode entries task with just specifying a
   * backend ID and nulls for list values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJustBackendIDNullLists()
         throws Exception
  {
    ReEncodeEntriesTask t = new ReEncodeEntriesTask(null, "userRoot", null,
         null, null, null, null, true, false);

    t = (ReEncodeEntriesTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new ReEncodeEntriesTask(t.getTaskPropertyValues());
    assertNotNull(t);

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getIncludeBranches());
    assertTrue(t.getIncludeBranches().isEmpty());

    assertNotNull(t.getExcludeBranches());
    assertTrue(t.getExcludeBranches().isEmpty());

    assertNotNull(t.getIncludeFilters());
    assertTrue(t.getIncludeFilters().isEmpty());

    assertNotNull(t.getExcludeFilters());
    assertTrue(t.getExcludeFilters().isEmpty());

    assertNull(t.getMaxEntriesPerSecond());

    assertTrue(t.skipFullyUncachedEntries());

    assertFalse(t.skipPartiallyUncachedEntries());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reencode"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior of the re-encode entries task with just specifying a
   * backend ID and empty list values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJustBackendIDEmptyLists()
         throws Exception
  {
    ReEncodeEntriesTask t = new ReEncodeEntriesTask(null, "userRoot",
         Collections.<String>emptyList(), Collections.<String>emptyList(),
         Collections.<String>emptyList(), Collections.<String>emptyList(), null,
         false, true);

    t = (ReEncodeEntriesTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new ReEncodeEntriesTask(t.getTaskPropertyValues());
    assertNotNull(t);

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getIncludeBranches());
    assertTrue(t.getIncludeBranches().isEmpty());

    assertNotNull(t.getExcludeBranches());
    assertTrue(t.getExcludeBranches().isEmpty());

    assertNotNull(t.getIncludeFilters());
    assertTrue(t.getIncludeFilters().isEmpty());

    assertNotNull(t.getExcludeFilters());
    assertTrue(t.getExcludeFilters().isEmpty());

    assertNull(t.getMaxEntriesPerSecond());

    assertFalse(t.skipFullyUncachedEntries());

    assertTrue(t.skipPartiallyUncachedEntries());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reencode"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior of the re-encode entries task with a complete set of
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteTaskArguments()
         throws Exception
  {
    ReEncodeEntriesTask t = new ReEncodeEntriesTask(null, "userRoot",
         Arrays.asList("dc=example,dc=com",
              "o=example.com"),
         Arrays.asList("ou=exclude,dc=example,dc=com",
              "ou=exclude,o=example.com"),
         Arrays.asList("(objectClass=*)"),
         Arrays.asList("(objectClass=exclude)"), 1234L, false, false);

    t = (ReEncodeEntriesTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new ReEncodeEntriesTask(t.getTaskPropertyValues());
    assertNotNull(t);

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getIncludeBranches());
    assertFalse(t.getIncludeBranches().isEmpty());
    assertEquals(t.getIncludeBranches().size(), 2);

    assertNotNull(t.getExcludeBranches());
    assertFalse(t.getExcludeBranches().isEmpty());
    assertEquals(t.getExcludeBranches().size(), 2);

    assertNotNull(t.getIncludeFilters());
    assertFalse(t.getIncludeFilters().isEmpty());
    assertEquals(t.getIncludeFilters().size(), 1);

    assertNotNull(t.getExcludeFilters());
    assertFalse(t.getExcludeFilters().isEmpty());
    assertEquals(t.getExcludeFilters().size(), 1);

    assertNotNull(t.getMaxEntriesPerSecond());
    assertEquals(t.getMaxEntriesPerSecond(), Long.valueOf(1234L));

    assertFalse(t.skipFullyUncachedEntries());

    assertFalse(t.skipPartiallyUncachedEntries());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reencode"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the ability to create a re-encode entries task from a minimal entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateTaskFromMinimalEntry()
         throws Exception
  {
    final ReEncodeEntriesTask t = new ReEncodeEntriesTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-reencode",
         "ds-task-id: test",
         "ds-task-class-name: " +
              "com.unboundid.directory.server.tasks.ReEncodeEntriesTask",
         "ds-task-state: waiting_on_start_time",
         "ds-task-reencode-backend-id: userRoot"));

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getIncludeBranches());
    assertTrue(t.getIncludeBranches().isEmpty());

    assertNotNull(t.getExcludeBranches());
    assertTrue(t.getExcludeBranches().isEmpty());

    assertNotNull(t.getIncludeFilters());
    assertTrue(t.getIncludeFilters().isEmpty());

    assertNotNull(t.getExcludeFilters());
    assertTrue(t.getExcludeFilters().isEmpty());

    assertNull(t.getMaxEntriesPerSecond());

    assertFalse(t.skipFullyUncachedEntries());

    assertFalse(t.skipPartiallyUncachedEntries());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reencode"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the ability to create a re-encode entries task from an entry that
   * doesn't contain a backend ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateTaskFromEntryMissingBackendID()
         throws Exception
  {
    new ReEncodeEntriesTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-reencode",
         "ds-task-id: test",
         "ds-task-class-name: " +
              "com.unboundid.directory.server.tasks.ReEncodeEntriesTask",
         "ds-task-state: waiting_on_start_time"));
  }



  /**
   * Tests the ability to create a re-encode entries task from a minimal set of
   * properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateTaskFromMinimalProperties()
         throws Exception
  {
    final LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(1);
    m.put(ReEncodeEntriesTask.PROPERTY_BACKEND_ID,
         Arrays.<Object>asList("userRoot"));

    final ReEncodeEntriesTask t = new ReEncodeEntriesTask(m);

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBackendID());
    assertEquals(t.getBackendID(), "userRoot");

    assertNotNull(t.getIncludeBranches());
    assertTrue(t.getIncludeBranches().isEmpty());

    assertNotNull(t.getExcludeBranches());
    assertTrue(t.getExcludeBranches().isEmpty());

    assertNotNull(t.getIncludeFilters());
    assertTrue(t.getIncludeFilters().isEmpty());

    assertNotNull(t.getExcludeFilters());
    assertTrue(t.getExcludeFilters().isEmpty());

    assertNull(t.getMaxEntriesPerSecond());

    assertFalse(t.skipFullyUncachedEntries());

    assertFalse(t.skipPartiallyUncachedEntries());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reencode"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the ability to create a re-encode entries task from an empty set of
   * properties (which should not be allowed because it's missing the backend
   * ID).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateTaskFromEmptyProperties()
         throws Exception
  {
    final LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(0);
    new ReEncodeEntriesTask(m);
  }
}
