/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the AlertTask class.
 */
public class AlertTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} alert type and message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NonNull()
         throws Exception
  {
    AlertTask t = new AlertTask("entering-lockdown-mode",
         "Time to go into lockdown mode");

    t = (AlertTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new AlertTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AlertTask");

    assertNotNull(t.getAlertType());
    assertEquals(t.getAlertType(), "entering-lockdown-mode");

    assertNotNull(t.getAlertMessage());
    assertEquals(t.getAlertMessage(), "Time to go into lockdown mode");

    assertNotNull(t.getAddDegradedAlertTypes());
    assertTrue(t.getAddDegradedAlertTypes().isEmpty());

    assertNotNull(t.getRemoveDegradedAlertTypes());
    assertTrue(t.getRemoveDegradedAlertTypes().isEmpty());

    assertNotNull(t.getAddUnavailableAlertTypes());
    assertTrue(t.getAddUnavailableAlertTypes().isEmpty());

    assertNotNull(t.getRemoveUnavailableAlertTypes());
    assertTrue(t.getRemoveUnavailableAlertTypes().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
         "ds-task-alert");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 2);

    assertNotNull(t.getTaskSpecificProperties());
    assertEquals(t.getTaskSpecificProperties().size(), 6);

    assertNotNull(t.getTaskPropertyValues());
    assertEquals(t.getTaskPropertyValues().size(), 2);
  }



  /**
   * Tests the first constructor with a {@code null} alert type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAlertType()
         throws Exception
  {
    new AlertTask(null, "foo");
  }



  /**
   * Tests the first constructor with a {@code null} alert message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAlertMessage()
         throws Exception
  {
    new AlertTask("entering-lockdown-mode", null);
  }



  /**
   * Tests the second constructor with values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2All()
         throws Exception
  {
    AlertTask t = new AlertTask("a", "b", Arrays.asList("c"),
         Arrays.asList("d", "e"), Arrays.asList("f", "g", "h"),
         Arrays.asList("i", "j", "k", "l"));

    t = (AlertTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new AlertTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AlertTask");

    assertNotNull(t.getAlertType());
    assertEquals(t.getAlertType(), "a");

    assertNotNull(t.getAlertMessage());
    assertEquals(t.getAlertMessage(), "b");

    assertNotNull(t.getAddDegradedAlertTypes());
    assertEquals(t.getAddDegradedAlertTypes().size(), 1);

    assertNotNull(t.getRemoveDegradedAlertTypes());
    assertEquals(t.getRemoveDegradedAlertTypes().size(), 2);

    assertNotNull(t.getAddUnavailableAlertTypes());
    assertEquals(t.getAddUnavailableAlertTypes().size(), 3);

    assertNotNull(t.getRemoveUnavailableAlertTypes());
    assertEquals(t.getRemoveUnavailableAlertTypes().size(), 4);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
         "ds-task-alert");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 6);

    assertNotNull(t.getTaskSpecificProperties());
    assertEquals(t.getTaskSpecificProperties().size(), 6);

    assertNotNull(t.getTaskPropertyValues());
    assertEquals(t.getTaskPropertyValues().size(), 6);
  }



  /**
   * Tests the second constructor without any values for the arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2None()
         throws Exception
  {
    new AlertTask(null, null, null, null, null, null);
  }



  /**
   * Tests the second constructor configured to only remove a value from the
   * set of unavailable alert types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2OnlyRemoveUnavailable()
         throws Exception
  {
    AlertTask t = new AlertTask(null, null, null, null, null,
         Arrays.asList("entering-lockdown-mode"));

    t = (AlertTask) Task.decodeTask(t.createTaskEntry());
    assertNotNull(t);

    t = new AlertTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AlertTask");

    assertNull(t.getAlertType());

    assertNull(t.getAlertMessage());

    assertNotNull(t.getAddDegradedAlertTypes());
    assertTrue(t.getAddDegradedAlertTypes().isEmpty());

    assertNotNull(t.getRemoveDegradedAlertTypes());
    assertTrue(t.getRemoveDegradedAlertTypes().isEmpty());

    assertNotNull(t.getAddUnavailableAlertTypes());
    assertTrue(t.getAddUnavailableAlertTypes().isEmpty());

    assertNotNull(t.getRemoveUnavailableAlertTypes());
    assertEquals(t.getRemoveUnavailableAlertTypes().size(), 1);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
         "ds-task-alert");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.getTaskSpecificProperties());
    assertEquals(t.getTaskSpecificProperties().size(), 6);

    assertNotNull(t.getTaskPropertyValues());
    assertEquals(t.getTaskPropertyValues().size(), 1);
  }



  /**
   * Tests the third constructor with an entry that has an alert type attribute
   * but none for the message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor3AlertTypeWithoutMessage()
         throws Exception
  {
    new AlertTask(new Entry(
         "dn: ds-task-id=foo,cn=Scheduled Tasks,cn=Tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-alert",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.AlertTask",
         "ds-task-alert-type: foo"));
  }



  /**
   * Tests the third constructor with an entry that has a message attribute but
   * but none for the alert type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor3AlertMessageWithoutType()
         throws Exception
  {
    new AlertTask(new Entry(
         "dn: ds-task-id=foo,cn=Scheduled Tasks,cn=Tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-alert",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.AlertTask",
         "ds-task-alert-message: bar"));
  }



  /**
   * Tests the third constructor with an entry that does not have any
   * alert-specific attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor3NoAlertAttributes()
         throws Exception
  {
    new AlertTask(new Entry(
         "dn: ds-task-id=foo,cn=Scheduled Tasks,cn=Tasks",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-alert",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.AlertTask"));
  }



  /**
   * Tests the fourth constructor with an empty map.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor4EmptyMap()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> m =
         new HashMap<TaskProperty,List<Object>>(0);

    new AlertTask(m);
  }



  /**
   * Tests the fourth constructor with a map containing an alert type without
   * an alert message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor4AlertTypeWithoutMessage()
         throws Exception
  {
    final List<TaskProperty> props =
         new AlertTask().getTaskSpecificProperties();
    final HashMap<TaskProperty,List<Object>> m =
         new HashMap<TaskProperty,List<Object>>(props.size());

    for (final TaskProperty p : props)
    {
      if (p.getAttributeName().equals("ds-task-alert-type"))
      {
        m.put(p, Arrays.<Object>asList("foo"));
      }
    }

    new AlertTask(m);
  }



  /**
   * Tests the fourth constructor with a map containing an alert message without
   * an alert type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor4AlertMessageWithoutType()
         throws Exception
  {
    final List<TaskProperty> props =
         new AlertTask().getTaskSpecificProperties();
    final HashMap<TaskProperty,List<Object>> m =
         new HashMap<TaskProperty,List<Object>>(props.size());

    for (final TaskProperty p : props)
    {
      if (p.getAttributeName().equals("ds-task-alert-message"))
      {
        m.put(p, Arrays.<Object>asList("foo"));
      }
    }

    new AlertTask(m);
  }
}
