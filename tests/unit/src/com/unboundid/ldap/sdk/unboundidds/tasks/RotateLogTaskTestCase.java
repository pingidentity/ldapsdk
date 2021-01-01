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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the RotateLogTask class.
 */
public class RotateLogTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the varargs constructor without any paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsNullPaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask("taskID", (String[]) null);

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertTrue(t.getPaths().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());
  }



  /**
   * Tests the varargs constructor without any paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsNoPaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask("taskID");

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertTrue(t.getPaths().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());
  }



  /**
   * Tests the varargs constructor with one path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsOnePath()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask(null, "logs/access");

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertEquals(t.getPaths().size(), 1);
    assertTrue(t.getPaths().contains("logs/access"));

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);
    assertTrue(t.getAdditionalAttributes().contains(
         new Attribute("ds-task-rotate-log-path", "logs/access")));
  }



  /**
   * Tests the varargs constructor with multiple paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsMultiplePaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask(null, "logs/access",
         "/ds/UnboundID-DS/logs/other-access");

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertEquals(t.getPaths().size(), 2);
    assertTrue(t.getPaths().contains("logs/access"));
    assertTrue(t.getPaths().contains("/ds/UnboundID-DS/logs/other-access"));

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);
    assertTrue(t.getAdditionalAttributes().contains(
         new Attribute("ds-task-rotate-log-path", "logs/access",
              "/ds/UnboundID-DS/logs/other-access")));
  }



  /**
   * Tests the collections constructor without any paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionsNullPaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask("taskID", (List<String>) null);

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertTrue(t.getPaths().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());
  }



  /**
   * Tests the collections constructor without any paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionsNoPaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask("taskID",
         Collections.<String>emptyList());

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertTrue(t.getPaths().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());
  }



  /**
   * Tests the collections constructor with one path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionsOnePath()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask(null,
         Collections.singletonList("logs/access"));

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertEquals(t.getPaths().size(), 1);
    assertTrue(t.getPaths().contains("logs/access"));

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);
    assertTrue(t.getAdditionalAttributes().contains(
         new Attribute("ds-task-rotate-log-path", "logs/access")));
  }



  /**
   * Tests the collections constructor with multiple paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionsMultiplePaths()
         throws Exception
  {
    RotateLogTask t = new RotateLogTask(null,
         Arrays.asList("logs/access", "/ds/UnboundID-DS/logs/other-access"));

    t = new RotateLogTask(t.getTaskPropertyValues());

    assertTrue(
         Task.decodeTask(t.createTaskEntry()) instanceof RotateLogTask);

    t = (RotateLogTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getPaths());
    assertEquals(t.getPaths().size(), 2);
    assertTrue(t.getPaths().contains("logs/access"));
    assertTrue(t.getPaths().contains("/ds/UnboundID-DS/logs/other-access"));

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(
         t.getAdditionalObjectClasses().contains("ds-task-rotate-log"));

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);
    assertTrue(t.getAdditionalAttributes().contains(
         new Attribute("ds-task-rotate-log-path", "logs/access",
              "/ds/UnboundID-DS/logs/other-access")));
  }
}
