/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
}
