/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
import java.util.HashMap;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the ReloadGlobalIndexTask class.
 */
public class ReloadGlobalIndexTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when configured with only a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithJustBaseDN()
         throws Exception
  {
    ReloadGlobalIndexTask t = new ReloadGlobalIndexTask(null,
         "dc=example,dc=com", null, null, null, null);

    t = new ReloadGlobalIndexTask(t.getTaskPropertyValues());
    assertNotNull(t);

    t = (ReloadGlobalIndexTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.proxy.tasks.ReloadTask");

    assertNotNull(t.getTaskID());

    assertNotNull(t.getBaseDN());
    assertDNsEqual(t.getBaseDN(), "dc=example,dc=com");

    assertNotNull(t.getIndexNames());
    assertTrue(t.getIndexNames().isEmpty());

    assertNull(t.reloadFromDS());

    assertNull(t.reloadInBackground());

    assertNull(t.getMaxEntriesPerSecond());

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reload-index"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior when configured with all task-specific properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithAllTaskSpecificProperties()
         throws Exception
  {
    ReloadGlobalIndexTask t = new ReloadGlobalIndexTask("test-task-id",
         "dc=example,dc=com", Arrays.asList("uid", "mail"), true, false, 1234L);

    t = new ReloadGlobalIndexTask(t.getTaskPropertyValues());
    assertNotNull(t);

    t = (ReloadGlobalIndexTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.proxy.tasks.ReloadTask");

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "test-task-id");

    assertNotNull(t.getBaseDN());
    assertDNsEqual(t.getBaseDN(), "dc=example,dc=com");

    assertNotNull(t.getIndexNames());
    assertEquals(t.getIndexNames().size(), 2);
    assertTrue(t.getIndexNames().contains("uid"));
    assertTrue(t.getIndexNames().contains("mail"));

    assertNotNull(t.reloadFromDS());
    assertEquals(t.reloadFromDS(), Boolean.TRUE);

    assertNotNull(t.reloadInBackground());
    assertEquals(t.reloadInBackground(), Boolean.FALSE);

    assertNotNull(t.getMaxEntriesPerSecond());
    assertEquals(t.getMaxEntriesPerSecond().longValue(), 1234L);

    assertNotNull(t.getAdditionalObjectClasses());
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-reload-index"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior when attempting to create a task from an entry that is
   * missing the required base DN attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromEntryMissingBaseDN()
         throws Exception
  {
    new ReloadGlobalIndexTask(new Entry(
         "dn: ds-task-id=test,cn=Scheduled Tasks,cn=tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-reload-index",
         "ds-task-id: test",
         "ds-task-reload-from-ds: true"));
  }



  /**
   * Tests the behavior when attempting to create a task from a property map
   * that is missing the required base DN property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testCreateFromPropertiesMissingBaseDN()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> propertyMap =
         new HashMap<TaskProperty,List<Object>>(10);
    propertyMap.put(ReloadGlobalIndexTask.PROPERTY_RELOAD_FROM_DS,
         Arrays.<Object>asList(Boolean.TRUE));

    new ReloadGlobalIndexTask(propertyMap);
  }
}
