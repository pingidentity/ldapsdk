/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020 Ping Identity Corporation
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
 * Copyright (C) 2020 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the GenerateServeProfileTask class.
 */
public class GenerateServerProfileTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    final GenerateServerProfileTask t = new GenerateServerProfileTask();

    assertNotNull(t.getTaskName());
    assertEquals(t.getTaskName(), "Generate Server Profile");

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());
    assertFalse(t.getTaskDescription().equals(t.getTaskName()));

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
         "ds-task-generate-server-profile");

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
    assertEquals(t.getTaskSpecificProperties().size(), 3);
  }



  /**
   * Test with with {@code null} values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullValuesForAllArguments()
         throws Exception
  {
    GenerateServerProfileTask t =
         new GenerateServerProfileTask(null, null, null, null);

    t = (GenerateServerProfileTask) Task.decodeTask(t.createTaskEntry());

    t = new GenerateServerProfileTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertNotNull(UUID.fromString(t.getTaskID()));

    assertNull(t.getProfileRoot());

    assertNotNull(t.getIncludePaths());
    assertTrue(t.getIncludePaths().isEmpty());

    assertNull(t.getZipProfile());
  }



  /**
   * Test with non-{@code null} values for all arguments, with one include path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllArgsOneIncludePath()
         throws Exception
  {
    final String profileRoot = createTempDir().getAbsolutePath();

    final List<String> includePaths = new ArrayList<>();
    includePaths.add("config/keystore");

    GenerateServerProfileTask t =
         new GenerateServerProfileTask(null, profileRoot, includePaths, false);

    t = (GenerateServerProfileTask) Task.decodeTask(t.createTaskEntry());

    t = new GenerateServerProfileTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertNotNull(UUID.fromString(t.getTaskID()));

    assertNotNull(t.getProfileRoot());
    assertEquals(t.getProfileRoot(), profileRoot);

    assertNotNull(t.getIncludePaths());
    assertFalse(t.getIncludePaths().isEmpty());
    assertEquals(t.getIncludePaths(), includePaths);

    assertNotNull(t.getZipProfile());
    assertFalse(t.getZipProfile());
  }



  /**
   * Test with non-{@code null} values for all arguments, with multiple include
   * paths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllArgsMultipleIncludePath()
         throws Exception
  {
    final String profileRoot = createTempDir().getAbsolutePath();

    final List<String> includePaths = new ArrayList<>();
    includePaths.add("config/keystore");
    includePaths.add("config/keystore.pin");

    GenerateServerProfileTask t =
         new GenerateServerProfileTask(null, profileRoot, includePaths, true);

    t = (GenerateServerProfileTask) Task.decodeTask(t.createTaskEntry());

    t = new GenerateServerProfileTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertNotNull(UUID.fromString(t.getTaskID()));

    assertNotNull(t.getProfileRoot());
    assertEquals(t.getProfileRoot(), profileRoot);

    assertNotNull(t.getIncludePaths());
    assertFalse(t.getIncludePaths().isEmpty());
    assertEquals(t.getIncludePaths(), includePaths);

    assertNotNull(t.getZipProfile());
    assertTrue(t.getZipProfile());
  }
}
