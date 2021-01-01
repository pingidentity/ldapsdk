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



import java.io.File;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the TaskManager class.
 */
public class TaskManagerTestCase
       extends LDAPSDKTestCase
{
  // Indicates whether a server is running on the local system.
  private boolean localServerAvailable;

  // The path to use for the backup directory in the temporary directory.
  private File bakDir;

  // The path to use for the LDIF file in the temporary directory.
  private File ldifFile;

  // The path to a temporary directory that can be used for these tests.
  private File tempDir;

  // The task ID used for the backup task.
  private String backupTaskID;

  // The task ID used for the dump DB details task.
  private String dumpDBDetailsTaskID;

  // The task ID used for the export task.
  private String exportTaskID;

  // The task ID used for the import task.
  private String importTaskID;

  // The task ID used for the rebuild task.
  private String rebuildTaskID;

  // The task ID used for the restore task.
  private String restoreTaskID;



  /**
   * Checks to see if a test server is available, and if so whether it is on the
   * local system.  If there is a server running on the local system, then
   * populate it with an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    localServerAvailable = false;
    if (isDirectoryInstanceAvailable())
    {
      try
      {
        InetAddress hostAddress = InetAddress.getByName(getTestHost());
        if (hostAddress.isLoopbackAddress())
        {
          localServerAvailable = true;
        }
      } catch (Exception e) {}
    }

    if (! localServerAvailable)
    {
      return;
    }

    tempDir = createTempFile();
    tempDir.delete();
    tempDir.mkdir();

    ldifFile = new File(tempDir, "test.ldif");

    bakDir = new File(tempDir, "bak");
    bakDir.mkdir();

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.close();
  }



  /**
   * Cleans up the temporary directory and clears the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    delete(tempDir);

    LDAPConnection conn = getAdminConnection();
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Tests the ability to perform an LDIF export using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduleExportTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    ExportTask exportTask =
         new ExportTask(null, "userRoot", ldifFile.getAbsolutePath());
    exportTaskID = exportTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(exportTask, conn);
      assertTrue(t instanceof ExportTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to perform an LDIF import using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleExportTask" })
  public void testScheduleImportTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    ImportTask importTask =
         new ImportTask(null, "userRoot", ldifFile.getAbsolutePath());
    importTaskID = importTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(importTask, conn);
      assertTrue(t instanceof ImportTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to back up a backend using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduleBackupTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    BackupTask backupTask =
         new BackupTask(null, bakDir.getAbsolutePath(), "userRoot");
    backupTaskID = backupTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(backupTask, conn);
      assertTrue(t instanceof BackupTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to restore a backend using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleBackupTask" })
  public void testScheduleRestoreTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    RestoreTask restoreTask =
         new RestoreTask(null, bakDir.getAbsolutePath(), "userRoot", false);
    restoreTaskID = restoreTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(restoreTask, conn);
      assertTrue(t instanceof RestoreTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to rebuild an index using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduleRebuildTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    RebuildTask rebuildTask =
         new RebuildTask(null, getTestBaseDN(), Arrays.asList("objectClass"));
    rebuildTaskID = rebuildTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(rebuildTask, conn);
      assertTrue(t instanceof RebuildTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to invoke the dump JE details task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduleDumpDBDetailsTask()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    DumpDBDetailsTask dumpDBDetailsTask =
         new DumpDBDetailsTask(null, "userRoot");

    dumpDBDetailsTaskID = dumpDBDetailsTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(dumpDBDetailsTask, conn);
      assertTrue(t instanceof DumpDBDetailsTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the {@code getTask} method when the target task does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetTaskNonexistent()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    // We can be pretty doggone confident that no task exists with this ID.
    String taskID = UUID.randomUUID().toString();

    LDAPConnection conn = getAdminConnection();
    try
    {
      assertNull(TaskManager.getTask(taskID, conn));
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the {@code getTasks} method to retrieve all tasks in the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleImportTask",
                             "testScheduleRestoreTask",
                             "testScheduleRebuildTask",
                             "testScheduleDumpDBDetailsTask" })
  public void testGetTasks()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      List<Task> tasks = TaskManager.getTasks(conn);
      assertNotNull(tasks);
      assertTrue(tasks.size() >= 5);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the {@code deleteTask} method to try removing the created task
   * entries from the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testGetTasks" })
  public void testDeleteTasks()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      TaskManager.deleteTask(exportTaskID, conn);
      TaskManager.deleteTask(importTaskID, conn);
      TaskManager.deleteTask(backupTaskID, conn);
      TaskManager.deleteTask(restoreTaskID, conn);
      TaskManager.deleteTask(rebuildTaskID, conn);
      TaskManager.deleteTask(dumpDBDetailsTaskID, conn);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to perform an LDIF export using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testDeleteTasks" })
  public void testScheduleExportTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    ExportTask exportTask = new ExportTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : exportTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-export-backend-id"))
      {
        props.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-export-ldif-file"))
      {
        props.put(p, Arrays.<Object>asList(ldifFile.getAbsolutePath()));
      }
    }

    exportTask = new ExportTask(props);
    exportTaskID = exportTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(exportTask, conn);
      assertTrue(t instanceof ExportTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to perform an LDIF import using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleExportTaskUsingProperties" })
  public void testScheduleImportTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    ImportTask importTask = new ImportTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : importTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-import-backend-id"))
      {
        props.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-task-import-ldif-file"))
      {
        props.put(p, Arrays.<Object>asList(ldifFile.getAbsolutePath()));
      }
    }

    importTask = new ImportTask(props);
    importTaskID = importTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(importTask, conn);
      assertTrue(t instanceof ImportTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to back up a backend using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testDeleteTasks" })
  public void testScheduleBackupTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    BackupTask backupTask = new BackupTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : backupTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-backup-backend-id"))
      {
        props.put(p, Arrays.<Object>asList("userRoot"));
      }
      else if (name.equals("ds-backup-directory-path"))
      {
        props.put(p, Arrays.<Object>asList(bakDir.getAbsolutePath()));
      }
    }

    backupTask = new BackupTask(props);
    backupTaskID = backupTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(backupTask, conn);
      assertTrue(t instanceof BackupTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to restore a backend using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleBackupTaskUsingProperties" })
  public void testScheduleRestoreTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    RestoreTask restoreTask = new RestoreTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : restoreTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-backup-directory-path"))
      {
        props.put(p, Arrays.<Object>asList(bakDir.getAbsolutePath()));
      }
    }

    restoreTask = new RestoreTask(props);
    restoreTaskID = restoreTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(restoreTask, conn);
      assertTrue(t instanceof RestoreTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to rebuild an index using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testDeleteTasks" })
  public void testScheduleRebuildTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    RebuildTask rebuildTask = new RebuildTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : rebuildTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-rebuild-base-dn"))
      {
        props.put(p, Arrays.<Object>asList(getTestBaseDN()));
      }
      else if (name.equals("ds-task-rebuild-index"))
      {
        props.put(p, Arrays.<Object>asList("objectClass"));
      }
    }

    rebuildTask = new RebuildTask(props);
    rebuildTaskID = rebuildTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(rebuildTask, conn);
      assertTrue(t instanceof RebuildTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to perform a dump DB details using a task.
   * <BR><BR>
   * Access to a Directory Server instance running on the local system is
   * required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testDeleteTasks" })
  public void testScheduleDumpDBDetailsTaskUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    DumpDBDetailsTask dumpDBDetailsTask = new DumpDBDetailsTask();
    HashMap<TaskProperty,List<Object>> props =
         new HashMap<TaskProperty,List<Object>>();

    for (TaskProperty p : dumpDBDetailsTask.getTaskSpecificProperties())
    {
      String name = toLowerCase(p.getAttributeName());
      if (name.equals("ds-task-dump-db-backend-id"))
      {
        props.put(p, Arrays.<Object>asList("userRoot"));
      }
    }

    dumpDBDetailsTask = new DumpDBDetailsTask(props);
    dumpDBDetailsTaskID = dumpDBDetailsTask.getTaskID();

    LDAPConnection conn = getAdminConnection();

    try
    {
      Task t = TaskManager.scheduleTask(dumpDBDetailsTask, conn);
      assertTrue(t instanceof DumpDBDetailsTask);

      t = TaskManager.waitForTask(t.getTaskID(), conn, 10L, 60000L);
      assert(t.isCompleted());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the {@code deleteTask} method to try removing the created task
   * entries from the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dependsOnMethods = { "testScheduleImportTaskUsingProperties",
                             "testScheduleRestoreTaskUsingProperties",
                             "testScheduleRebuildTaskUsingProperties",
                             "testScheduleDumpDBDetailsTaskUsingProperties" })
  public void testDeleteTasksUsingProperties()
         throws Exception
  {
    if (! localServerAvailable)
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      TaskManager.deleteTask(exportTaskID, conn);
      TaskManager.deleteTask(importTaskID, conn);
      TaskManager.deleteTask(backupTaskID, conn);
      TaskManager.deleteTask(restoreTaskID, conn);
      TaskManager.deleteTask(rebuildTaskID, conn);
      TaskManager.deleteTask(dumpDBDetailsTaskID, conn);
    }
    finally
    {
      conn.close();
    }
  }
}
