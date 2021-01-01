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



import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the RefreshEncryptionSettingsTask
 * class.
 */
public class RefreshEncryptionSettingsTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithTaskID()
         throws Exception
  {
    final RefreshEncryptionSettingsTask t =
         new RefreshEncryptionSettingsTask("foo");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.RefreshEncryptionSettingsTask");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-refresh-encryption-settings");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 0);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} task ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithoutTaskID()
         throws Exception
  {
    final RefreshEncryptionSettingsTask t =
         new RefreshEncryptionSettingsTask((String) null);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.RefreshEncryptionSettingsTask");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-refresh-encryption-settings");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 0);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the entry-based with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor4Valid(final Entry e)
         throws Exception
  {
    final RefreshEncryptionSettingsTask t =
         new RefreshEncryptionSettingsTask(e);

    assertNotNull(t);

    assertNotNull(t.getTaskEntry());
    assertEquals(t.getTaskEntry(), e);

    assertNotNull(t.getTaskEntryDN());
    assertEquals(new DN(t.getTaskEntryDN()),
                 new DN(e.getDN()));

    assertNotNull(t.getTaskID());

    assertNotNull(t.getTaskClassName());

    assertNotNull(t.getState());

    assertNotNull(t.getDependencyIDs());

    assertNotNull(t.getLogMessages());

    assertNotNull(t.getNotifyOnCompletionAddresses());

    assertNotNull(t.getNotifyOnErrorAddresses());

    assertNotNull(t.getAdditionalObjectClasses());

    assertNotNull(t.getAdditionalAttributes());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof RefreshEncryptionSettingsTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid refresh encryption
   * settings task definitions.
   *
   * @return  A set of entries that may be parsed as valid refresh encryption
   *          settings task definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "validEntries")
  public Object[][] getValidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=validTask1,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-refresh-encryption-settings",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server." +
                       "tasks.RefreshEncryptionSettingsTask",
                  "ds-task-state: waiting_on_start_time")
      }
    };
  }



  /**
   * Tests the entry-based constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testConstructor4Invalid(final Entry e)
         throws Exception
  {
    new RefreshEncryptionSettingsTask(e);
  }



  /**
   * Tests the {@code decodeTask} method with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries")
  public void testDecodeTask(final Entry e)
         throws Exception
  {
    try
    {
      assertFalse(Task.decodeTask(e) instanceof RefreshEncryptionSettingsTask);
    }
    catch (final TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid refresh
   * encryption settings task definitions.
   *
   * @return  A set of entries that cannot be parsed as valid refresh encryption
   *          settings task definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "invalidEntries")
  public Object[][] getInvalidEntries()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        new Entry("dn: ds-task-id=fails in superclass,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: not-ds-task",
                  "ds-task-id: fails in superclass",
                  "ds-task-class-name: com.unboundid.directory.server." +
                       "tasks.RefreshEncryptionSettingsTask",
                  "ds-task-state: waiting_on_start_time")
      }
    };
  }



  /**
   * Tests the property-based constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesConstructor()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>(0);

    final RefreshEncryptionSettingsTask t =
         new RefreshEncryptionSettingsTask(properties);

    final Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (final TaskProperty p : Task.getCommonTaskProperties())
    {
      if (props.get(p) == null)
      {
        continue;
      }

      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (final Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (final TaskProperty p : t.getTaskSpecificProperties())
    {
      assertNotNull(props.get(p));
      if (p.isRequired())
      {
        assertFalse(props.get(p).isEmpty());
      }

      if (! p.isMultiValued())
      {
        assertFalse(props.get(p).size() > 1);
      }

      for (final Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }
}
