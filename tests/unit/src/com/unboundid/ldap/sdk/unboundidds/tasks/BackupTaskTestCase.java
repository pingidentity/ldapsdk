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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the BackupTask class.
 */
public class BackupTaskTestCase
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
    BackupTask t = new BackupTask("foo", "bak/userRoot", "userRoot");

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.BackupTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak/userRoot");

    assertNotNull(t.getBackendIDs());
    assertEquals(t.getBackendIDs().size(), 1);
    assertEquals(t.getBackendIDs().get(0), "userRoot");

    assertFalse(t.backupAll());

    assertNull(t.getBackupID());

    assertFalse(t.incremental());

    assertNull(t.getIncrementalBaseID());

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertFalse(t.hash());

    assertFalse(t.signHash());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNull(t.getRetainPreviousFullBackupCount());

    assertNull(t.getRetainPreviousFullBackupAge());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} backend ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoBackendID()
         throws Exception
  {
    BackupTask t = new BackupTask("foo", "bak", null);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.BackupTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertTrue(t.getBackendIDs().isEmpty());

    assertTrue(t.backupAll());

    assertNull(t.getBackupID());

    assertFalse(t.incremental());

    assertNull(t.getIncrementalBaseID());

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertFalse(t.hash());

    assertFalse(t.signHash());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNull(t.getRetainPreviousFullBackupCount());

    assertNull(t.getRetainPreviousFullBackupAge());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());
  }



  /**
   * Tests the first constructor with a {@code null} backup directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoBackupDirectory()
         throws Exception
  {
    new BackupTask("foo", null, "userRoot");
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
    List<String> backendIDs = Arrays.asList("userRoot", "adminRoot");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    BackupTask t = new BackupTask("foo", "bak", backendIDs, "baz", true, "bar",
                                  true, false, true, false, d, dependencyIDs,
                                  FailedDependencyAction.CANCEL,
                                  notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.BackupTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertEquals(t.getBackendIDs().size(), 2);
    assertEquals(t.getBackendIDs().get(0), "userRoot");
    assertEquals(t.getBackendIDs().get(1), "adminRoot");

    assertFalse(t.backupAll());

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "baz");

    assertTrue(t.incremental());

    assertNotNull(t.getIncrementalBaseID());
    assertEquals(t.getIncrementalBaseID(), "bar");

    assertTrue(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertTrue(t.hash());

    assertFalse(t.signHash());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNull(t.getRetainPreviousFullBackupCount());

    assertNull(t.getRetainPreviousFullBackupAge());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

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
    List<String> backendIDs = Arrays.asList("userRoot", "adminRoot");
    List<String> dependencyIDs = Arrays.asList("dep1", "dep2");
    List<String> notifyOnCompletion = Arrays.asList("peon@example.com");
    List<String> notifyOnError = Arrays.asList("admin@example.com");

    Date d = new Date();

    BackupTask t = new BackupTask("foo", "bak", backendIDs, "baz", true, "bar",
         true, true, "passphrase.txt", "definition", true, true, 100, 5,
         "3 days", d, dependencyIDs, FailedDependencyAction.CANCEL,
         notifyOnCompletion, notifyOnError);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.BackupTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertEquals(t.getBackendIDs().size(), 2);
    assertEquals(t.getBackendIDs().get(0), "userRoot");
    assertEquals(t.getBackendIDs().get(1), "adminRoot");

    assertFalse(t.backupAll());

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "baz");

    assertTrue(t.incremental());

    assertNotNull(t.getIncrementalBaseID());
    assertEquals(t.getIncrementalBaseID(), "bar");

    assertTrue(t.compress());

    assertTrue(t.encrypt());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(t.getEncryptionSettingsDefinitionID());
    assertEquals(t.getEncryptionSettingsDefinitionID(), "definition");

    assertTrue(t.hash());

    assertTrue(t.signHash());

    assertNotNull(t.getMaxMegabytesPerSecond());
    assertEquals(t.getMaxMegabytesPerSecond().intValue(), 100);

    assertNotNull(t.getRetainPreviousFullBackupCount());
    assertEquals(t.getRetainPreviousFullBackupCount().intValue(), 5);

    assertNotNull(t.getRetainPreviousFullBackupAge());
    assertEquals(t.getRetainPreviousFullBackupAge(), "3 days");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

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
    List<String> backendIDs = Collections.emptyList();
    BackupTask t = new BackupTask("foo", "bak", Collections.<String>emptyList(),
                                  null, false, null, false, false, true, false,
                                  null, null, null, null, null);

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
                 "com.unboundid.directory.server.tasks.BackupTask");

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertTrue(t.getBackendIDs().isEmpty());

    assertTrue(t.backupAll());

    assertNull(t.getBackupID());

    assertFalse(t.incremental());

    assertNull(t.getIncrementalBaseID());

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertNull(t.getEncryptionPassphraseFile());

    assertNull(t.getEncryptionSettingsDefinitionID());

    assertTrue(t.hash());

    assertFalse(t.signHash());

    assertNull(t.getMaxMegabytesPerSecond());

    assertNull(t.getRetainPreviousFullBackupCount());

    assertNull(t.getRetainPreviousFullBackupAge());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

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
    BackupTask t = new BackupTask(e);

    assertNotNull(t);

    assertNotNull(t.getBackupDirectory());

    assertNotNull(t.getBackendIDs());

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
                 "ds-task-backup");

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.createTaskEntry());

    assertNotNull(Task.decodeTask(e));
    assertTrue(Task.decodeTask(e) instanceof BackupTask);
  }



  /**
   * Retrieves a set of entries that may be parsed as valid backup task
   * definitions.
   *
   * @return  A set of entries that may be parsed as valid backup task
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
                  "objectclass: ds-task-backup",
                  "ds-task-id: validTask1",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=validTask2,cn=Scheduled Tasks,cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: validTask2",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_dependency",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-backend-id: adminRoot",
                  "ds-task-backup-all: false",
                  "ds-backup-id: my-backup",
                  "ds-task-backup-incremental: true",
                  "ds-task-backup-incremental-base-id: old-backup",
                  "ds-task-backup-compress: true",
                  "ds-task-backup-encrypt: true",
                  "ds-task-backup-hash: true",
                  "ds-task-backup-sign-hash: true",
                  "ds-task-backup-encryption-settings-passphrase-file: pw.txt",
                  "ds-task-backup-encryption-settings-definition-id: def",
                  "ds-task-backup-max-megabytes-per-second: 100",
                  "ds-task-backup-retain-previous-full-backup-count: 5",
                  "ds-task-backup-retain-previous-full-backup-age: 3 days",
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
    new BackupTask(e);
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
      assertFalse(Task.decodeTask(e) instanceof BackupTask);
    }
    catch (TaskException te)
    {
      // This is expected for some failure cases.
    }
  }



  /**
   * Retrieves a set of entries that cannot be parsed as valid backup task
   * definitions.
   *
   * @return  A set of entries that cannot be parsed as valid backup task
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
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=no backup directory,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: no backup directory",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-task-backup-backend-id: userRoot")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid incremental,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: invalid incremental",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-incremental: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid compress,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: invalid compress",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-compress: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid encrypt,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: invalid encrypt",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-encrypt: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid hash,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: invalid hash",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-hash: invalid")
      },

      new Object[]
      {
        new Entry("dn: ds-task-id=invalid sign hash,cn=Scheduled Tasks," +
                       "cn=tasks",
                  "objectClass: top",
                  "objectclass: ds-task",
                  "objectclass: ds-task-backup",
                  "ds-task-id: invalid sign hash",
                  "ds-task-class-name: com.unboundid.directory.server.tasks." +
                       "BackupTask",
                  "ds-task-state: waiting_on_start_time",
                  "ds-backup-directory-path: bak/userRoot",
                  "ds-task-backup-backend-id: userRoot",
                  "ds-task-backup-sign-hash: invalid")
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

    for (TaskProperty p : new BackupTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-backup-directory-path"))
      {
        properties.put(p, Arrays.<Object>asList("bak"));
      }
      else if (name.equals("ds-task-backup-backend-id"))
      {
        properties.put(p, Arrays.<Object>asList("userRoot", "adminRoot"));
      }
      else if (name.equals("ds-backup-id"))
      {
        properties.put(p, Arrays.<Object>asList("foo"));
      }
      else if (name.equals("ds-task-backup-compress"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-backup-encrypt"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-backup-encryption-passphrase-file"))
      {
        properties.put(p, Arrays.<Object>asList("passphrase.txt"));
      }
      else if (name.equals("ds-task-backup-encryption-settings-definition-id"))
      {
        properties.put(p, Arrays.<Object>asList("definition"));
      }
      else if (name.equals("ds-task-backup-hash"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-backup-sign-hash"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-backup-max-megabytes-per-second"))
      {
        properties.put(p, Arrays.<Object>asList(Long.valueOf(100)));
      }
      else if (name.equals("ds-task-backup-retain-previous-full-backup-count"))
      {
        properties.put(p, Arrays.<Object>asList(Long.valueOf(5)));
      }
      else if (name.equals("ds-task-backup-retain-previous-full-backup-age"))
      {
        properties.put(p, Arrays.<Object>asList("3 days"));
      }
      else if (name.equals("ds-task-backup-incremental"))
      {
        properties.put(p, Arrays.<Object>asList(Boolean.TRUE));
      }
      else if (name.equals("ds-task-backup-incremental-base-id"))
      {
        properties.put(p, Arrays.<Object>asList("bar"));
      }
    }

    BackupTask t = new BackupTask(properties);

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertEquals(t.getBackendIDs().size(), 2);

    assertFalse(t.backupAll());

    assertNotNull(t.getBackupID());
    assertEquals(t.getBackupID(), "foo");

    assertTrue(t.incremental());

    assertNotNull(t.getIncrementalBaseID());
    assertEquals(t.getIncrementalBaseID(), "bar");

    assertTrue(t.compress());

    assertTrue(t.encrypt());

    assertNotNull(t.getEncryptionPassphraseFile());
    assertEquals(t.getEncryptionPassphraseFile(), "passphrase.txt");

    assertNotNull(t.getEncryptionSettingsDefinitionID());
    assertEquals(t.getEncryptionSettingsDefinitionID(), "definition");

    assertTrue(t.hash());

    assertTrue(t.signHash());

    assertNotNull(t.getMaxMegabytesPerSecond());
    assertEquals(t.getMaxMegabytesPerSecond().intValue(), 100);

    assertNotNull(t.getRetainPreviousFullBackupCount());
    assertEquals(t.getRetainPreviousFullBackupCount().intValue(), 5);

    assertNotNull(t.getRetainPreviousFullBackupAge());
    assertEquals(t.getRetainPreviousFullBackupAge(), "3 days");

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

    for (TaskProperty p : new BackupTask().getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-backup-directory-path"))
      {
        properties.put(p, Arrays.<Object>asList("bak"));
      }
    }

    BackupTask t = new BackupTask(properties);

    assertNotNull(t.getBackupDirectory());
    assertEquals(t.getBackupDirectory(), "bak");

    assertNotNull(t.getBackendIDs());
    assertEquals(t.getBackendIDs().size(), 0);

    assertTrue(t.backupAll());

    assertNull(t.getBackupID());

    assertFalse(t.incremental());

    assertNull(t.getIncrementalBaseID());

    assertFalse(t.compress());

    assertFalse(t.encrypt());

    assertFalse(t.hash());

    assertFalse(t.signHash());

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
    new BackupTask(properties);
  }
}
