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



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the TaskState class.
 */
public class TaskStateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for TaskState values.
   *
   * @param  s  The task state value to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "taskStates")
  public void testTaskState(final TaskState s)
         throws Exception
  {
    assertNotNull(s);

    assertEquals(TaskState.valueOf(s.name()), s);

    assertEquals(TaskState.forName(s.getName()), s);

    assertNotNull(s.getName());
    assertNotNull(s.toString());
  }



  /**
   * Tests the {@code isPending} method.
   *
   * @param  s  The task state value to examine.
   */
  @Test(dataProvider = "taskStates")
  public void testIsPending(final TaskState s)
  {
    switch (s)
    {
      case DISABLED:
      case UNSCHEDULED:
      case WAITING_ON_DEPENDENCY:
      case WAITING_ON_START_TIME:
        assertTrue(s.isPending());
        break;

      case CANCELED_BEFORE_STARTING:
      case COMPLETED_SUCCESSFULLY:
      case COMPLETED_WITH_ERRORS:
      case RUNNING:
      case STOPPED_BY_ADMINISTRATOR:
      case STOPPED_BY_ERROR:
      case STOPPED_BY_SHUTDOWN:
        assertFalse(s.isPending());
        break;

      default:
        fail("Unexpected task state:  " + s.name());
    }
  }



  /**
   * Tests the {@code isRunning} method.
   *
   * @param  s  The task state value to examine.
   */
  @Test(dataProvider = "taskStates")
  public void testIsRunning(final TaskState s)
  {
    if (s == TaskState.RUNNING)
    {
      assertTrue(s.isRunning());
    }
    else
    {
      assertFalse(s.isRunning());
    }
  }



  /**
   * Tests the {@code isCompleted} method.
   *
   * @param  s  The task state value to examine.
   */
  @Test(dataProvider = "taskStates")
  public void testIsCompleted(final TaskState s)
  {
    switch (s)
    {
      case CANCELED_BEFORE_STARTING:
      case COMPLETED_SUCCESSFULLY:
      case COMPLETED_WITH_ERRORS:
      case STOPPED_BY_ADMINISTRATOR:
      case STOPPED_BY_ERROR:
      case STOPPED_BY_SHUTDOWN:
        assertTrue(s.isCompleted());
        break;

      case DISABLED:
      case RUNNING:
      case UNSCHEDULED:
      case WAITING_ON_DEPENDENCY:
      case WAITING_ON_START_TIME:
        assertFalse(s.isCompleted());
        break;

      default:
        fail("Unexpected task state:  " + s.name());
    }
  }



  /**
   * Retrieves the set of defined task states.
   *
   * @return  The set of defined task states.
   */
  @DataProvider(name = "taskStates")
  public Object[][] getTaskStates()
  {
    TaskState[] values = TaskState.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }



  /**
   * Tests the {@code forName} method with an invalid value.
   */
  @Test()
  public void testForNameInvalid()
  {
    assertNull(TaskState.forName("invalid"));
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final TaskState value : TaskState.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(TaskState.forName(name));
        assertEquals(TaskState.forName(name), value);
      }
    }

    assertNull(TaskState.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
