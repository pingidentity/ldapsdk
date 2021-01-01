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
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the GroovyScriptedTask class.
 */
public class GroovyScriptedTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} task ID,
   * non-{@code null} class name, and non-empty argument list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithTaskID()
         throws Exception
  {
    final GroovyScriptedTask t = new GroovyScriptedTask("foo",
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask",
         Arrays.asList(
              "base-dn=dc=example,dc=com",
              "scope=sub",
              "filter=(uid=test.user)",
              "output-file=ldif/example-task.ldif"));

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.sdk.extensions.GroovyScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskClassName());
    assertEquals(t.getGroovyScriptedTaskClassName(),
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskArguments());
    assertFalse(t.getGroovyScriptedTaskArguments().isEmpty());
    assertEquals(t.getGroovyScriptedTaskArguments().size(), 4);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-groovy-scripted-task");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 2);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} task ID and no arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithoutTaskIDOrArguments()
         throws Exception
  {
    final GroovyScriptedTask t = new GroovyScriptedTask(null,
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask",
         null);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.sdk.extensions.GroovyScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskClassName());
    assertEquals(t.getGroovyScriptedTaskClassName(),
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskArguments());
    assertTrue(t.getGroovyScriptedTaskArguments().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-groovy-scripted-task");

    assertNotNull(t.getAdditionalAttributes());
    assertEquals(t.getAdditionalAttributes().size(), 1);

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} task ID and
   * {@code null} class name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1WithoutTaskIDOrClassName()
         throws Exception
  {
    new GroovyScriptedTask(null, null, null);
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
    final GroovyScriptedTask t = new GroovyScriptedTask(e);

    assertNotNull(t);

    assertNotNull(t.getGroovyScriptedTaskClassName());

    assertNotNull(t.getGroovyScriptedTaskArguments());

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
    assertTrue(Task.decodeTask(e) instanceof GroovyScriptedTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid Groovy-scripted task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid Groovy-scripted task
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
                  "objectclass: ds-groovy-scripted-task",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.sdk." +
                       "extensions.GroovyScriptedTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-scripted-task-class: " +
                       "com.unboundid.directory.sdk.extensions.groovy." +
                       "ExampleScriptedTask")
      },

      new Object[]
      {
           new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                     "objectClass: top",
                     "objectclass: ds-task",
                     "objectclass: ds-groovy-scripted-task",
                     "ds-task-id: validTask2",
                     "ds-task-class-name: com.unboundid.directory.sdk." +
                          "extensions.GroovyScriptedTask",
                     "ds-task-state: waiting_on_start_time",
                     "ds-scripted-task-class: " +
                          "com.unboundid.directory.sdk.extensions.groovy." +
                          "ExampleScriptedTask",
                     "ds-scripted-task-argument: base-dn=dc=example,dc=com",
                     "ds-scripted-task-argument: scope=sub",
                     "ds-scripted-task-argument: filter=(uid=test.user)",
                     "ds-scripted-task-argument: output-file=/tmp/test.ldif")
      }
    };
  }



  /**
   * Tests the entry-based with an invalid test entry.
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
    new GroovyScriptedTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof GroovyScriptedTask);
    }
    catch (final TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid Groovy-scripted
   * task definitions.
   *
   * @return  A set of entries that cannot be parsed as valid Groovy-scripted
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
                  "ds-task-class-name: com.unboundid.directory.sdk." +
                       "extensions.GroovyScriptedTask",
                  "ds-task-state: waiting_on_start_time",
             "ds-scripted-task-class: " +
                  "com.unboundid.directory.sdk.extensions.groovy." +
                  "ExampleScriptedTask")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no class name,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-groovy-scripted-task",
                  "ds-task-id: fails in superclass",
                  "ds-task-class-name: com.unboundid.directory.sdk." +
                       "extensions.GroovyScriptedTask",
                  "ds-task-state: waiting_on_start_time")
      }
    };
  }



  /**
   * Tests the property-based constructor with just a class name but no
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesConstructorNoArguments()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>(1);

    properties.put(GroovyScriptedTask.PROPERTY_TASK_CLASS,
         Arrays.<Object>asList("com.unboundid.directory.sdk.examples." +
              "groovy.ExampleScriptedTask"));

    final GroovyScriptedTask t = new GroovyScriptedTask(properties);

    assertNotNull(t.getGroovyScriptedTaskClassName());
    assertEquals(t.getGroovyScriptedTaskClassName(),
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskArguments());
    assertTrue(t.getGroovyScriptedTaskArguments().isEmpty());

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



  /**
   * Tests the property-based constructor with a class name and arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesConstructorWithArguments()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>(2);

    properties.put(GroovyScriptedTask.PROPERTY_TASK_CLASS,
         Arrays.<Object>asList("com.unboundid.directory.sdk.examples.groovy." +
              "ExampleScriptedTask"));
    properties.put(GroovyScriptedTask.PROPERTY_TASK_ARG, Arrays.<Object>asList(
         "base-dn=dc=example,dc=com",
         "scope=sub",
         "filter=(uid=test.user)",
         "data-file=/tmp/test.ldif"));

    final GroovyScriptedTask t = new GroovyScriptedTask(properties);

    assertNotNull(t.getGroovyScriptedTaskClassName());
    assertEquals(t.getGroovyScriptedTaskClassName(),
         "com.unboundid.directory.sdk.examples.groovy.ExampleScriptedTask");

    assertNotNull(t.getGroovyScriptedTaskArguments());
    assertFalse(t.getGroovyScriptedTaskArguments().isEmpty());

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



  /**
   * Tests the properties-based constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testPropertiesConstructorEmpty()
         throws Exception
  {
    final HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>(0);
    new GroovyScriptedTask(properties);
  }
}
