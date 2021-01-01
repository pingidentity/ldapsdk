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

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the RebuildTask class.
 */
public class RebuildTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Valid()
         throws Exception
  {
    List<String> indexes = Arrays.asList("uid", "cn");

    RebuildTask t = new RebuildTask("foo", "dc=example,dc=com", indexes);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RebuildTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(t.getIndexNames());
    assertEquals(t.getIndexNames().size(), 2);
    assertEquals(t.getIndexNames().get(0), "uid");
    assertEquals(t.getIndexNames().get(1), "cn");

    assertFalse(t.getMaxRebuildThreads() > 0);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-rebuild");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with no base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoBaseDN()
         throws Exception
  {
    List<String> indexes = Arrays.asList("uid", "cn");

    new RebuildTask("foo", null, indexes);
  }



  /**
   * Tests the first constructor with a {@code null} index list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullIndexes()
         throws Exception
  {
    new RebuildTask("foo", "dc=example,dc=com", null);
  }



  /**
   * Tests the first constructor with an empty index list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1EmptyIndexes()
         throws Exception
  {
    new RebuildTask("foo", "dc=example,dc=com", Arrays.<String>asList());
  }



  /**
   * Tests the second constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2All()
         throws Exception
  {
    List<String> indexes = Arrays.asList("uid", "cn");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    RebuildTask t = new RebuildTask("foo", "dc=example,dc=com", indexes, 10,
                                    d, dependencyIDs,
                                    FailedDependencyAction.CANCEL,
                                    notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RebuildTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(t.getIndexNames());
    assertEquals(t.getIndexNames().size(), 2);
    assertEquals(t.getIndexNames().get(0), "uid");
    assertEquals(t.getIndexNames().get(1), "cn");

    assertEquals(t.getMaxRebuildThreads(), 10);

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-rebuild");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the third constructor with a valid test entry.
   *
   * @param  e  The valid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validEntries")
  public void testConstructor3Valid(final Entry e)
         throws Exception
  {
    RebuildTask t = new RebuildTask(e);

    assertNotNull(t);

    assertNotNull(t.getBaseDN());

    assertNotNull(t.getIndexNames());
    assertFalse(t.getIndexNames().isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-rebuild");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof RebuildTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid rebuild task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid rebuild task
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
                  "objectclass: ds-task-rebuild",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RebuildTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-rebuild-base-dn: dc=example,dc=com",
                  "ds-task-rebuild-index: cn")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-rebuild",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RebuildTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-task-rebuild-base-dn: dc=example,dc=com",
                  "ds-task-rebuild-index: cn",
                  "ds-task-rebuild-index: sn",
                  "ds-task-rebuild-max-threads: 25",
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
      },
    };
  }



  /**
   * Tests the third constructor with an invalid test entry.
   *
   * @param  e  The invalid entry to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidEntries",
        expectedExceptions = { TaskException.class })
  public void testConstructor3Invalid(final Entry e)
         throws Exception
  {
    new RebuildTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof RebuildTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid rebuild task
   * definitions.
   *
   * @return  A set of entries that cannot be parsed as valid rebuild task
   *          definitions.
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
                       "RebuildTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no base dn,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-rebuild",
                  "ds-task-id: no base dn",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RebuildTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-rebuild-index: cn")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no index,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-rebuild",
                  "ds-task-id: no index",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RebuildTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-rebuild-base-dn: dc=example,dc=com")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid max threads,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-rebuild",
                  "ds-task-id: invalid max threads",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RebuildTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-rebuild-base-dn: dc=example,dc=com",
                  "ds-task-rebuild-index: cn",
                  "ds-task-rebuild-max-threads: invalid")
      }
    };
  }



  /**
   * Tests the fourth constructor with values for all properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4All()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new RebuildTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-rebuild-base-dn"))
      {
        properties.put(p, Arrays.<Object>asList("dc=example,dc=com"));
      }
      else if (name.equals("ds-task-rebuild-index"))
      {
        properties.put(p, Arrays.<Object>asList("cn", "sn"));
      }
      else if (name.equals("ds-task-rebuild-max-threads"))
      {
        properties.put(p, Arrays.<Object>asList(Long.valueOf(10)));
      }
    }

    RebuildTask t = new RebuildTask(properties);

    assertNotNull(t.getBaseDN());
    assertEquals(t.getBaseDN(), "dc=example,dc=com");

    assertNotNull(t.getIndexNames());
    assertEquals(t.getIndexNames().size(), 2);

    assertEquals(t.getMaxRebuildThreads(), 10);

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
   * Tests the fourth constructor with values for all required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4AllRequired()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : new RebuildTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-rebuild-base-dn"))
      {
        properties.put(p, Arrays.<Object>asList("dc=example,dc=com"));
      }
      else if (name.equals("ds-task-rebuild-index"))
      {
        properties.put(p, Arrays.<Object>asList("cn", "sn"));
      }
    }

    RebuildTask t = new RebuildTask(properties);

    assertNotNull(t.getBaseDN());
    assertEquals(t.getBaseDN(), "dc=example,dc=com");

    assertNotNull(t.getIndexNames());
    assertEquals(t.getIndexNames().size(), 2);

    assertTrue(t.getMaxRebuildThreads() <= 0);

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
   * Tests the fourth constructor without any values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testConstructor4Empty()
         throws Exception
  {
    HashMap<TaskProperty,List<Object>> properties =
         new HashMap<TaskProperty,List<Object>>();
    new RebuildTask(properties);
  }
}
