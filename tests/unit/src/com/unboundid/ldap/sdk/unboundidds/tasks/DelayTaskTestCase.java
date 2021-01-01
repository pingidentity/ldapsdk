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



import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPURL;



/**
 * This class provides test coverage for the DelayTask class.
 */
public class DelayTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor that does not take any
   * arguments.
   */
  @Test()
  public void testDefaultConstructor()
  {
    final DelayTask t = new DelayTask();

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-delay"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior for a task instance that does not have any delays.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateTaskWithNoDelays()
         throws Exception
  {
    DelayTask t = new DelayTask(null, null, null, null, null, null, null);

    t = (DelayTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new DelayTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.DelayTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNull(t.getSleepDurationMillis());

    assertNull(t.getMillisToWaitForWorkQueueToBecomeIdle());

    assertNotNull(t.getLDAPURLsForSearchesExpectedToReturnEntries());
    assertTrue(t.getLDAPURLsForSearchesExpectedToReturnEntries().isEmpty());

    assertNull(t.getMillisBetweenSearches());

    assertNull(t.getSearchTimeLimitMillis());

    assertNull(t.getTotalDurationMillisForEachLDAPURL());

    assertNull(t.getTaskStateIfTimeoutIsEncountered());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-delay"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertTrue(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior for a task instance that has all types of delays.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateTaskWithAllTypesOfDelays()
         throws Exception
  {
    DelayTask t = new DelayTask(1234L, 5678L,
         Arrays.asList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)"),
              new LDAPURL("ldap:///cn=monitor??base?(available=true)")),
         1L, 10L, 30_000L, TaskState.COMPLETED_WITH_ERRORS);

    t = (DelayTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new DelayTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.DelayTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getSleepDurationMillis());
    assertEquals(t.getSleepDurationMillis(), Long.valueOf(1234L));

    assertNotNull(t.getMillisToWaitForWorkQueueToBecomeIdle());
    assertEquals(t.getMillisToWaitForWorkQueueToBecomeIdle(),
         Long.valueOf(5678L));

    assertNotNull(t.getLDAPURLsForSearchesExpectedToReturnEntries());
    assertFalse(t.getLDAPURLsForSearchesExpectedToReturnEntries().isEmpty());
    assertEquals(t.getLDAPURLsForSearchesExpectedToReturnEntries().size(), 2);

    assertNotNull(t.getMillisBetweenSearches());
    assertEquals(t.getMillisBetweenSearches(), Long.valueOf(1L));

    assertNotNull(t.getSearchTimeLimitMillis());
    assertEquals(t.getSearchTimeLimitMillis(), Long.valueOf(10L));

    assertNotNull(t.getTotalDurationMillisForEachLDAPURL());
    assertEquals(t.getTotalDurationMillisForEachLDAPURL(),
         Long.valueOf(30_000L));

    assertNotNull(t.getTaskStateIfTimeoutIsEncountered());
    assertEquals(t.getTaskStateIfTimeoutIsEncountered(),
         TaskState.COMPLETED_WITH_ERRORS.name());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-delay"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertFalse(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior when trying to create a delay task with a negative
   * sleep duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testNegativeSleepDuration()
         throws Exception
  {
    new DelayTask(-1234L, null, null, null, null, null, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a negative
   * work queue idle duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testNegativeWorkQueueIdleDuration()
         throws Exception
  {
    new DelayTask(null, -5678L, null, null, null, null, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a negative
   * search interval.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testNegativeSearchInterval()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         -1L, 10L, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a negative
   * search time limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testNegativeSearchTimeLimit()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         1L, -10L, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a negative
   * search duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testNegativeSearchDuration()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         1L, 10L, -30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a search
   * interval that is greater than the search duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testSearchIntervalGreaterThanDuration()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         60_000L, 10L, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a search
   * time limit that is equal to the search duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testSearchTimeLimitEqualToDuration()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         1L, 30_000L, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a search URL
   * without a search interval.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testSearchURLWithoutInterval()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         null, 30_000L, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a search URL
   * without a search time limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testSearchURLWithoutTimeLimit()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         1L, null, 30_000L, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with a search URL
   * without a search duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testSearchURLWithoutDuration()
         throws Exception
  {
    new DelayTask(null, null,
         Collections.singletonList(
              new LDAPURL("ldap:///dc=example,dc=com??base?(objectClass=*)")),
         1L, 10L, null, null);
  }



  /**
   * Tests the behavior when trying to create a delay task with an invalid
   * timeout return state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testInvalidTimeoutReturnState()
         throws Exception
  {
    new DelayTask(null, null, null, null, null, null,
         TaskState.DISABLED);
  }



  /**
   * Tests the behavior when trying to create a delay task from an empty entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromEmptyEntry()
         throws Exception
  {
    final DelayTask t = new DelayTask(new Entry(
         "dn: ds-task-id=Empty Delay Task Entry,cn=Scheduled Tasks,cn=config",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-delay",
         "ds-task-id: Empty Delay Task",
         "ds-task-class-name: " + DelayTask.DELAY_TASK_CLASS));

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.DelayTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNull(t.getSleepDurationMillis());

    assertNull(t.getMillisToWaitForWorkQueueToBecomeIdle());

    assertNotNull(t.getLDAPURLsForSearchesExpectedToReturnEntries());
    assertTrue(t.getLDAPURLsForSearchesExpectedToReturnEntries().isEmpty());

    assertNull(t.getMillisBetweenSearches());

    assertNull(t.getSearchTimeLimitMillis());

    assertNull(t.getTotalDurationMillisForEachLDAPURL());

    assertNull(t.getTaskStateIfTimeoutIsEncountered());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-delay"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskPropertyValues());
    assertTrue(t.getTaskPropertyValues().isEmpty());
  }



  /**
   * Tests the behavior when trying to create a delay task from an entry that
   * has a malformed duration value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromEntryWithInvalidDuration()
         throws Exception
  {
    new DelayTask(new Entry(
         "dn: ds-task-id=Delay Task Entry with Invalid Duration,cn=Scheduled " +
              "Tasks,cn=config",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-delay",
         "ds-task-id: Delay Task Entry with Invalid Duration",
         "ds-task-class-name: " + DelayTask.DELAY_TASK_CLASS,
         "ds-task-delay-sleep-duration: not a valid duration"));
  }



  /**
   * Tests the behavior when trying to create a delay task from an entry that
   * has a URL value that can't be parsed as an LDAP URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromEntryWithInvalidURL()
         throws Exception
  {
    new DelayTask(new Entry(
         "dn: ds-task-id=Delay Task Entry with Invalid URL,cn=Scheduled " +
              "Tasks,cn=config",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-delay",
         "ds-task-id: Delay Task Entry with Invalid URL",
         "ds-task-class-name: " + DelayTask.DELAY_TASK_CLASS,
         "ds-task-delay-ldap-url-for-search-expected-to-return-entries: " +
              "not a valid URL"));
  }



  /**
   * Tests the behavior when trying to create a delay task from a set of
   * properties that contains a list of URL strings that contains an invalid
   * URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromPropertyMapWithInvalidURL()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> properties =
         new HashMap<>(1);
    for (final TaskProperty p : new DelayTask().getTaskSpecificProperties())
    {
      if (p.getAttributeName().equals(
           "ds-task-delay-ldap-url-for-search-expected-to-return-entries"))
      {
        properties.put(p,
             Collections.<Object>singletonList("not a valid URL"));
      }
    }

    new DelayTask(properties);
  }
}
