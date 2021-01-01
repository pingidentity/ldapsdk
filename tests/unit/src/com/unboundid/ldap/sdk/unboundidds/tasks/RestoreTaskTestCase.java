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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the RestoreTask class.
 */
public class RestoreTaskTestCase
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
    RestoreTask t = new RestoreTask("foo", "bak/userRoot", "my-backup", false);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RestoreTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "my-backup");

    assertFalse(t.verifyOnly());

    assertNull(t.getEncryptionPassphraseFile());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with no backup ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoBackupID()
         throws Exception
  {
    RestoreTask t = new RestoreTask("foo", "bak/userRoot", null, true);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RestoreTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNull(t.getBackupID());

    assertTrue(t.verifyOnly());

    assertNull(t.getEncryptionPassphraseFile());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with no backup directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoBackupDirectory()
         throws Exception
  {
    new RestoreTask("foo", null, "my-backup", false);
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
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    RestoreTask t = new RestoreTask("foo", "bak/userRoot", "my-backup", false,
                                    d, dependencyIDs,
                                    FailedDependencyAction.CANCEL,
                                    notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RestoreTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "my-backup");

    assertFalse(t.verifyOnly());

    assertNull(t.getEncryptionPassphraseFile());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2bAll()
         throws Exception
  {
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    RestoreTask t = new RestoreTask("foo", "bak/userRoot", "my-backup", false,
                                    "passphrase.txt", d, dependencyIDs,
                                    FailedDependencyAction.CANCEL,
                                    notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RestoreTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "my-backup");

    assertFalse(t.verifyOnly());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the second constructor with a minimal set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Minimal()
         throws Exception
  {
    RestoreTask t = new RestoreTask(null, "bak/userRoot", null, true, null,
                                    null, null, null, null);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.RestoreTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNull(t.getBackupID());

    assertTrue(t.verifyOnly());

    assertNull(t.getEncryptionPassphraseFile());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

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
    RestoreTask t = new RestoreTask(e);

    assertNotNull(t);

    assertNotNull(t.getBackupDirectory());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-restore");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof RestoreTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid restore task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid restore task
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
                  "objectclass: ds-task-restore",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RestoreTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-restore",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RestoreTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-backup-id: my-backup",
                  "ds-verify-only: false",
                  "ds-task-restore-encryption-passphrase-file: passphrase.txt",
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
    new RestoreTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof RestoreTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid restore task
   * definitions.
   *
   * @return  A set of entries that cannot be parsed as valid restore task
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
                       "RestoreTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no backup directory,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-restore",
                  "ds-task-id: no backup directory",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RestoreTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=valid verify only,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-restore",
                  "ds-task-id: invalid verify only",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "RestoreTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-restore-verify-only: invalid")
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

    for (TaskProperty p : new RestoreTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-backup-directory-path"))
      {
        properties.put(p, Arrays.<Object>asList("bak/userRoot"));
      }
      else if (name.equals("ds-backup-id"))
      {
        properties.put(p, Arrays.<Object>asList("foo"));
      }
      else if (name.equals("ds-task-restore-verify-only"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-restore-encryption-passphrase-file"))
      {
        properties.put(p, Arrays.<Object>asList("passphrase.txt"));
      }
    }

    RestoreTask t = new RestoreTask(properties);

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "foo");

    assertTrue(t.verifyOnly());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

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

    for (TaskProperty p : new RestoreTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-backup-directory-path"))
      {
        properties.put(p, Arrays.<Object>asList("bak/userRoot"));
      }
    }

    RestoreTask t = new RestoreTask(properties);

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNull(t.getBackupID());

    assertFalse(t.verifyOnly());

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
    new RestoreTask(properties);
  }
}
