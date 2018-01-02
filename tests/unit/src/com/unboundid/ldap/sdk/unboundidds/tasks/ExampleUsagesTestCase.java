/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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



import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code TaskManager} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testTaskManagerExample()
         throws Exception
  {
    // NOTE:  The in-memory directory server doesn't currently support this
    // capability, so this test won't actually do anything except verify that
    // the code compiles.  That's why this test is disabled.

    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    List<Task> allTasks = TaskManager.getTasks(connection);
    for (Task task : allTasks)
    {
      String taskID = task.getTaskID();
      String taskName = task.getTaskName();
      TaskState taskState = task.getState();
      Map<TaskProperty,List<Object>> taskProperties =
           task.getTaskPropertyValues();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }
}
