/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;
import static com.unboundid.util.Validator.*;



/**
 * This class defines a Directory Server task that can be used to restore a
 * backup.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>The path to the backup directory in which the backup resides.  This
 *       must be provided when scheduling a new task of this type.</LI>
 *   <LI>The backup ID of the backup to be restored.  If this is not provided
 *       when scheduling an instance of this task, then the most recent backup
 *       in the backup directory will be selected.</LI>
 *   <LI>A flag that indicates whether to attempt to restore the backup or
 *       only to verify it to determine whether it appears to be valid (e.g.,
 *       validate the digest and/or signature, make sure that the backend
 *       considers it valid, etc.).</LI>
 * </UL>

 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RestoreTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the restore
   * task.
   */
  static final String RESTORE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RestoreTask";



  /**
   * The name of the attribute used to specify the path to the backup directory
   * containing the backup to restore.
   */
  private static final String ATTR_BACKUP_DIRECTORY =
       "ds-backup-directory-path";



  /**
   * The name of the attribute used to specify the backup ID of the backup to
   * restore.
   */
  private static final String ATTR_BACKUP_ID = "ds-backup-id";



  /**
   * The name of the attribute used to indicate whether to only verify the
   * backup but not actually restore it.
   */
  private static final String ATTR_VERIFY_ONLY =
       "ds-task-restore-verify-only";



  /**
   * The name of the object class used in restore task entries.
   */
  private static final String OC_RESTORE_TASK = "ds-task-restore";



  /**
   * The task property for the backup directory.
   */
  private static final TaskProperty PROPERTY_BACKUP_DIRECTORY =
       new TaskProperty(ATTR_BACKUP_DIRECTORY,
                        INFO_DISPLAY_NAME_BACKUP_DIRECTORY.get(),
                        INFO_DESCRIPTION_BACKUP_DIRECTORY_RESTORE.get(),
                        String.class, true, false, false);



  /**
   * The task property for the backup ID.
   */
  private static final TaskProperty PROPERTY_BACKUP_ID =
       new TaskProperty(ATTR_BACKUP_ID, INFO_DISPLAY_NAME_BACKUP_ID.get(),
                        INFO_DESCRIPTION_BACKUP_ID_RESTORE.get(), String.class,
                        false, false, true);



  /**
   * The task property for the verify only flag.
   */
  private static final TaskProperty PROPERTY_VERIFY_ONLY =
       new TaskProperty(ATTR_VERIFY_ONLY, INFO_DISPLAY_NAME_VERIFY_ONLY.get(),
                        INFO_DESCRIPTION_VERIFY_ONLY.get(), Boolean.class,
                        false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -196339437379274643L;



  // Indicates whether to only verify the backup without restoring it.
  private final boolean verifyOnly;

  // The path to the backup directory containing the backup to restore.
  private final String backupDirectory;

  // The backup ID of the backup to restore.
  private final String backupID;



  /**
   * Creates a new uninitialized restore task instance which should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public RestoreTask()
  {
    verifyOnly      = false;
    backupDirectory = null;
    backupID        = null;
  }




  /**
   * Creates a new restore task with the provided information.
   *
   * @param  taskID           The task ID to use for this task.  If it is
   *                          {@code null} then a UUID will be generated for use
   *                          as the task ID.
   * @param  backupDirectory  The path to the directory on the server containing
   *                          the backup to restore.  It may be an absolute path
   *                          or relative to the server root directory.  It must
   *                          not be {@code null}.
   * @param  backupID         The backup ID of the backup to restore.  If this
   *                          is {@code null} then the most recent backup in the
   *                          specified backup directory will be restored.
   * @param  verifyOnly       Indicates whether to only verify the backup
   *                          without restoring it.
   */
  public RestoreTask(final String taskID, final String backupDirectory,
                     final String backupID, final boolean verifyOnly)
  {
    this(taskID, backupDirectory, backupID, verifyOnly, null, null, null, null,
         null);
  }



  /**
   * Creates a new restore task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  backupDirectory         The path to the directory on the server
   *                                 containing the backup to restore.  It may
   *                                 be an absolute path or relative to the
   *                                 server root directory.  It must not be
   *                                 {@code null}.
   * @param  backupID                The backup ID of the backup to restore.  If
   *                                 this is {@code null} then the most recent
   *                                 backup in the specified backup directory
   *                                 will be restored.
   * @param  verifyOnly              Indicates whether to only verify the backup
   *                                 without restoring it.
   * @param  scheduledStartTime      The time that this task should start
   *                                 running.
   * @param  dependencyIDs           The list of task IDs that will be required
   *                                 to complete before this task will be
   *                                 eligible to start.
   * @param  failedDependencyAction  Indicates what action should be taken if
   *                                 any of the dependencies for this task do
   *                                 not complete successfully.
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   */
  public RestoreTask(final String taskID, final String backupDirectory,
                     final String backupID, final boolean verifyOnly,
                     final Date scheduledStartTime,
                     final List<String> dependencyIDs,
                     final FailedDependencyAction failedDependencyAction,
                     final List<String> notifyOnCompletion,
                     final List<String> notifyOnError)
  {
    super(taskID, RESTORE_TASK_CLASS, scheduledStartTime,
          dependencyIDs, failedDependencyAction, notifyOnCompletion,
          notifyOnError);

    ensureNotNull(backupDirectory);

    this.backupDirectory = backupDirectory;
    this.backupID        = backupID;
    this.verifyOnly      = verifyOnly;
  }



  /**
   * Creates a new restore task from the provided entry.
   *
   * @param  entry  The entry to use to create this restore task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a restore
   *                         task entry.
   */
  public RestoreTask(final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the backup directory.  It must be present.
    backupDirectory = entry.getAttributeValue(ATTR_BACKUP_DIRECTORY);
    if (backupDirectory == null)
    {
      throw new TaskException(ERR_RESTORE_NO_BACKUP_DIRECTORY.get(
                                   getTaskEntryDN()));
    }


    // Get the backup ID.  It may be absent.
    backupID = entry.getAttributeValue(ATTR_BACKUP_ID);


    // Get the verifyOnly flag.  It may be absent.
    verifyOnly = parseBooleanValue(entry, ATTR_VERIFY_ONLY, false);
  }



  /**
   * Creates a new restore task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid restore task.
   */
  public RestoreTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(RESTORE_TASK_CLASS, properties);

    boolean v = false;
    String  b = null;
    String  i = null;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BACKUP_DIRECTORY))
      {
        b = parseString(p, values, b);
      }
      else if (attrName.equalsIgnoreCase(ATTR_BACKUP_ID))
      {
        i = parseString(p, values, i);
      }
      else if (attrName.equalsIgnoreCase(ATTR_VERIFY_ONLY))
      {
        v = parseBoolean(p, values, v);
      }
    }

    if (b == null)
    {
      throw new TaskException(ERR_RESTORE_NO_BACKUP_DIRECTORY.get(
                                   getTaskEntryDN()));
    }

    backupDirectory = b;
    backupID        = i;
    verifyOnly      = v;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_RESTORE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_RESTORE.get();
  }



  /**
   * Retrieves the path to the backup directory which contains the backup to
   * restore.  It may be either an absolute path or one that is relative to the
   * server root.
   *
   * @return  The path to the backup directory which contains the backup to
   *          restore.
   */
  public String getBackupDirectory()
  {
    return backupDirectory;
  }



  /**
   * Retrieves the backup ID of the backup to restore.
   *
   * @return  The backup ID of the backup to restore, or {@code null} if the
   *          most recent backup in the backup directory should be restored.
   */
  public String getBackupID()
  {
    return backupID;
  }



  /**
   * Indicates whether the backup should only be verified without actually being
   * restored.
   *
   * @return  {@code true} if the backup should be verified but not restored, or
   *          {@code false} if it should be restored.
   */
  public boolean verifyOnly()
  {
    return verifyOnly;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_RESTORE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<Attribute>(3);

    attrs.add(new Attribute(ATTR_BACKUP_DIRECTORY, backupDirectory));
    attrs.add(new Attribute(ATTR_VERIFY_ONLY, String.valueOf(verifyOnly)));

    if (backupID != null)
    {
      attrs.add(new Attribute(ATTR_BACKUP_ID, backupID));
    }

    return attrs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    final List<TaskProperty> propList = Arrays.asList(
         PROPERTY_BACKUP_DIRECTORY,
         PROPERTY_BACKUP_ID,
         PROPERTY_VERIFY_ONLY);

    return Collections.unmodifiableList(propList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>();

    props.put(PROPERTY_BACKUP_DIRECTORY,
         Collections.<Object>unmodifiableList(Arrays.asList(backupDirectory)));

    if (backupID == null)
    {
      props.put(PROPERTY_BACKUP_ID, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_BACKUP_ID,
                Collections.<Object>unmodifiableList(Arrays.asList(backupID)));
    }

    props.put(PROPERTY_VERIFY_ONLY,
              Collections.<Object>unmodifiableList(Arrays.asList(verifyOnly)));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
