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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the AddSchemaFileTask class.
 */
public class AddSchemaFileTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} task ID and
   * non-{@code null} schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithTaskID()
         throws Exception
  {
    AddSchemaFileTask t = new AddSchemaFileTask("foo", "bar");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 1);
    assertEquals(t.getSchemaFileNames().get(0), "bar");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} task ID and
   * non-{@code null} schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithoutTaskID()
         throws Exception
  {
    AddSchemaFileTask t = new AddSchemaFileTask(null, "bar");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 1);
    assertEquals(t.getSchemaFileNames().get(0), "bar");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} task ID and
   * {@code null} schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1WithoutTaskIDOrSchemaFile()
         throws Exception
  {
    new AddSchemaFileTask(null, (String) null);
  }



  /**
   * Tests the second constructor with a single schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleSchemaFile()
         throws Exception
  {
    List<String> files = Arrays.asList("bar");

    AddSchemaFileTask t = new AddSchemaFileTask("foo", files);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 1);
    assertEquals(t.getSchemaFileNames().get(0), "bar");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with multiple schema files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleSchemaFiles()
         throws Exception
  {
    List<String> files = Arrays.asList("bar", "baz");

    AddSchemaFileTask t = new AddSchemaFileTask("foo", files);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 2);
    assertEquals(t.getSchemaFileNames().get(0), "bar");
    assertEquals(t.getSchemaFileNames().get(1), "baz");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with an empty set of schema files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2EmptySchemaFiles()
         throws Exception
  {
    new AddSchemaFileTask("foo", (List<String>) null);
  }



  /**
   * Tests the third constructor with non-{@code null} but empty lists for
   * superclass elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithEmptyLists()
         throws Exception
  {
    List<String> schemaFiles = Arrays.asList("bar", "baz");

    Date d = new Date();

    AddSchemaFileTask t =
         new AddSchemaFileTask("foo", schemaFiles, d,
                               Collections.<String>emptyList(),
                               FailedDependencyAction.DISABLE,
                               Collections.<String>emptyList(),
                               Collections.<String>emptyList());

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 2);
    assertEquals(t.getSchemaFileNames().get(0), "bar");
    assertEquals(t.getSchemaFileNames().get(1), "baz");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the third constructor with non-empty lists for superclass elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithNonEmptyLists()
         throws Exception
  {
    List<String> schemaFiles = Arrays.asList("bar", "baz");

    Date d = new Date();

    List<String> dependencyIDs = Arrays.asList("dependency1", "dependency2");

    List<String> notifyOnCompletion =
         Arrays.asList("junior-admin-1@example.com",
                       "junior-admin-2@example.com",
                       "junior-admin-3@example.com");

    List<String> notifyOnError =
         Arrays.asList("senior-admin-1@example.com",
                       "senior-admin-2@example.com",
                       "senior-admin-3@example.com",
                       "senior-admin-4@example.com");


    AddSchemaFileTask t =
         new AddSchemaFileTask("foo", schemaFiles, d, dependencyIDs,
                               FailedDependencyAction.CANCEL,
                               notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.AddSchemaFileTask");

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 2);
    assertEquals(t.getSchemaFileNames().get(0), "bar");
    assertEquals(t.getSchemaFileNames().get(1), "baz");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-add-schema-file");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the fourth constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor4Valid(final Entry e)
         throws Exception
  {
    AddSchemaFileTask t = new AddSchemaFileTask(e);

    assertNotNull(t);

    assertNotNull(t.getSchemaFileNames());
    assertFalse(t.getSchemaFileNames().isEmpty());

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
    assertTrue(Task.decodeTask(e) instanceof AddSchemaFileTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid add schema file task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid add schema file task
   *          definitions.
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
                  "objectclass: ds-task-add-schema-file",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "AddSchemaFileTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-schema-file-name: foo")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-add-schema-file",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "AddSchemaFileTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-schema-file-name: foo",
                  "ds-task-schema-file-name: bar",
                  "ds-task-scheduled-start-time: 20080101000000Z",
                  "ds-task-actual-start-time: 20080101000000Z",
                  "ds-task-completion-time: 20080101010101Z",
                  "ds-task-dependency-id: validTask1",
                  "ds-task-failed-dependency-action: cancel",
                  "ds-task-log-message: [01/Jan/2008:00:00:00 +0000] starting",
                  "ds-task-log-message: [01/Jan/2008:01:01:01 +0000] done",
                  "ds-task-notify-on-completion: ray@example.com",
                  "ds-task-notify-on-completion: winston@example.com",
                  "ds-task-notify-on-error: peter@example.com",
                  "ds-task-notify-on-error: egon@example.com")
      }
    };
  }



  /**
   * Tests the fourth constructor with an invalid test entry.
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
    new AddSchemaFileTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof AddSchemaFileTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid add schema file
   * task definitions.
   *
   * @return  A set of entries that cannot be parsed as valid add schema file
   *          task definitions.
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
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "AddSchemaFileTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-schema-file-name: foo")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no schema files,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-add-schema-file",
                  "ds-task-id: fails in superclass",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "AddSchemaFileTask",
                  "ds-task-state: waiting_on_start_time")
      }
    };
  }



  /**
   * Tests the fifth constructor with a single schema file name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Single()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new AddSchemaFileTask().getTaskSpecificProperties())
    {
      properties.put(p, Arrays.<Object>asList("foo.ldif"));
    }

    AddSchemaFileTask t = new AddSchemaFileTask(properties);

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 1);

    Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (TaskProperty p : Task.getCommonTaskProperties())
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

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (TaskProperty p : t.getTaskSpecificProperties())
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

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }



  /**
   * Tests the fifth constructor with a multiple schema file names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Multiple()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new AddSchemaFileTask().getTaskSpecificProperties())
    {
      properties.put(p, Arrays.<Object>asList("foo.ldif", "bar.ldif"));
    }

    AddSchemaFileTask t = new AddSchemaFileTask(properties);

    assertNotNull(t.getSchemaFileNames());
    assertEquals(t.getSchemaFileNames().size(), 2);

    Map<TaskProperty,List<Object>> props = t.getTaskPropertyValues();
    for (TaskProperty p : Task.getCommonTaskProperties())
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

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }

    for (TaskProperty p : t.getTaskSpecificProperties())
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

      for (Object v : props.get(p))
      {
        assertNotNull(v);
        assertEquals(v.getClass(), p.getDataType());
      }
    }
  }



  /**
   * Tests the fifth constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor5Empty()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    new AddSchemaFileTask(properties);
  }
}
