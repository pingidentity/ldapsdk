/*
 * Copyright 2018-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2019 Ping Identity Corporation
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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the ExecTask class.
 */
public class ExecTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor that does not take any
   * arguments.
   */
  @Test()
  public void testDefaultConstructor()
  {
    final ExecTask t = new ExecTask();

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-exec"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior when trying to create an exec task with values for all
   * of the exec-related arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithValuesForAllArguments()
         throws Exception
  {
    ExecTask t = new ExecTask("/path/to/command", "command arguments",
         "/path/to/output", true, TaskState.STOPPED_BY_ERROR);

    t = (ExecTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new ExecTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.ExecTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getCommandPath());
    assertEquals(t.getCommandPath(), "/path/to/command");

    assertNotNull(t.getCommandArguments());
    assertEquals(t.getCommandArguments(), "command arguments");

    assertNotNull(t.getCommandOutputFile());
    assertEquals(t.getCommandOutputFile(), "/path/to/output");

    assertNotNull(t.logCommandOutput());
    assertEquals(t.logCommandOutput(), Boolean.TRUE);

    assertNotNull(t.getTaskStateForNonZeroExitCode());
    assertEquals(t.getTaskStateForNonZeroExitCode(),
         TaskState.STOPPED_BY_ERROR.name());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-exec"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 5);

    assertNotNull(t.getTaskSpecificProperties());
    assertEquals(t.getTaskSpecificProperties().size(), 5);

    assertNotNull(t.getTaskPropertyValues());
    assertEquals(t.getTaskPropertyValues().size(), 5);
  }



  /**
   * Tests the behavior when trying to create an exec task with only a value for
   * the required path argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithOnlyPathArgument()
         throws Exception
  {
    ExecTask t = new ExecTask("/path/to/command", null, null, null, null);

    t = (ExecTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new ExecTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.ExecTask");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getCommandPath());
    assertEquals(t.getCommandPath(), "/path/to/command");

    assertNull(t.getCommandArguments());

    assertNull(t.getCommandOutputFile());

    assertNull(t.logCommandOutput());

    assertNull(t.getTaskStateForNonZeroExitCode());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses(),
         Collections.singletonList("ds-task-exec"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.getTaskSpecificProperties());
    assertEquals(t.getTaskSpecificProperties().size(), 5);

    assertNotNull(t.getTaskPropertyValues());
    assertEquals(t.getTaskPropertyValues().size(), 1);
  }



  /**
   * Tests the behavior when trying to create an exec task with a {@code null}
   * path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateWithNullPath()
         throws Exception
  {
    new ExecTask(null, null, null, null, null);
  }



  /**
   * Tests the behavior when trying to create an exec task with an inappropriate
   * task state for use with a nonzero exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateWithInappropriateNonZeroExitCodeState()
         throws Exception
  {
    new ExecTask("/path/to/command", null, null, null,
         TaskState.WAITING_ON_START_TIME);
  }



  /**
   * Tests the behavior when trying to create an exec task from an entry without
   * any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromEntryWithoutAttributes()
         throws Exception
  {
    new ExecTask(new Entry(
         "dn: ds-task-id=missing-path,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-exec",
         "ds-task-id: missing-path",
         "ds-task-class-name: com.unboundid.directory.server.tasks.ExecTask"));
  }



  /**
   * Tests the behavior when trying to create an exec task from an empty set of
   * properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromEmptyPropertyMap()
         throws Exception
  {
    new ExecTask(Collections.<TaskProperty,List<Object>>emptyMap());
  }
}
