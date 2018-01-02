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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;
import static com.unboundid.util.Validator.*;



/**
 * This class defines a Directory Server task that can be used to back up one or
 * more Directory Server backends.
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
 *   <LI>The path to the directory in which the backup should be placed.  If
 *       multiple backends are to be backed up at once, then this should be the
 *       parent of the backup directories for each backend.  This must be
 *       provided when scheduling this task.</LI>
 *   <LI>The backend IDs of the backends to archive.  If this is not provided,
 *       then the server will attempt to back up all supported backends.</LI>
 *   <LI>The backup ID to use for the backup.  If this is not provided, then the
 *       server will generate a backup ID.</LI>
 *   <LI>A flag that indicates whether the backup should be an incremental
 *       backup (if the backend supports that capability) or a full backup.</LI>
 *   <LI>The backup ID of the existing backup on which the incremental backup
 *       should be based.  If this is not provided and an incremental backup
 *       is to be performed, then it will be based on the most recent backup in
 *       the backup directory.</LI>
 *   <LI>A flag that indicates whether to compress the contents of the
 *       backup.</LI>
 *   <LI>A flag that indicates whether to encrypt the contents of the
 *       backup.</LI>
 *   <LI>A flag that indicates whether to hash the contents of the backup to use
 *       as a checksum for verifying the integrity of the backup.</LI>
 *   <LI>A flag that indicates whether to sign the backup hash in order to
 *       prevent anyone from tampering with it.</LI>
 * </UL>

 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BackupTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the backup
   * task.
   */
  static final String BACKUP_TASK_CLASS =
       "com.unboundid.directory.server.tasks.BackupTask";



  /**
   * The name of the attribute used to specify backend IDs of the backends to
   * archive.
   */
  private static final String ATTR_BACKEND_ID = "ds-task-backup-backend-id";



  /**
   * The name of the attribute used to indicate whether to back up the contents
   * of all supported backends.
   */
  private static final String ATTR_BACKUP_ALL = "ds-task-backup-all";



  /**
   * The name of the attribute used to specify the path to the directory in
   * which the backup is to be written.
   */
  private static final String ATTR_BACKUP_DIRECTORY =
       "ds-backup-directory-path";



  /**
   * The name of the attribute used to specify the backup ID for the backup.
   */
  private static final String ATTR_BACKUP_ID = "ds-backup-id";



  /**
   * The name of the attribute used to indicate whether to compress the backup.
   */
  private static final String ATTR_COMPRESS = "ds-task-backup-compress";



  /**
   * The name of the attribute used to indicate whether to encrypt the backup.
   */
  private static final String ATTR_ENCRYPT = "ds-task-backup-encrypt";



  /**
   * The name of the attribute used to indicate whether to create a hash of the
   * backup.
   */
  private static final String ATTR_HASH = "ds-task-backup-hash";



  /**
   * The name of the attribute used to indicate whether to perform an
   * incremental backup rather than a full backup.
   */
  private static final String ATTR_INCREMENTAL = "ds-task-backup-incremental";



  /**
   * The name of the attribute used to specify the backup ID of the backup
   * on which to base the incremental backup.
   */
  private static final String ATTR_INCREMENTAL_BASE_ID =
       "ds-task-backup-incremental-base-id";



  /**
   * The name of the attribute used to indicate whether to sign the hash of the
   * backup.
   */
  private static final String ATTR_SIGN_HASH = "ds-task-backup-sign-hash";



  /**
   * The name of the object class used in backup task entries.
   */
  private static final String OC_BACKUP_TASK = "ds-task-backup";



  /**
   * The task property that will be used for the backup directory.
   */
  private static final TaskProperty PROPERTY_BACKUP_DIRECTORY =
       new TaskProperty(ATTR_BACKUP_DIRECTORY,
                        INFO_DISPLAY_NAME_BACKUP_DIRECTORY.get(),
                        INFO_DESCRIPTION_BACKUP_DIRECTORY_BACKUP.get(),
                        String.class, true, false, false);



  /**
   * The task property that will be used for the backend ID.
   */
  private static final TaskProperty PROPERTY_BACKEND_ID =
       new TaskProperty(ATTR_BACKEND_ID, INFO_DISPLAY_NAME_BACKEND_ID.get(),
                        INFO_DESCRIPTION_BACKEND_ID_BACKUP.get(), String.class,
                        false, true, false);



  /**
   * The task property that will be used for the backup ID.
   */
  private static final TaskProperty PROPERTY_BACKUP_ID =
       new TaskProperty(ATTR_BACKUP_ID, INFO_DISPLAY_NAME_BACKUP_ID.get(),
                        INFO_DESCRIPTION_BACKUP_ID_BACKUP.get(), String.class,
                        false, false, true);



  /**
   * The task property that will be used for the incremental flag.
   */
  private static final TaskProperty PROPERTY_INCREMENTAL =
       new TaskProperty(ATTR_INCREMENTAL, INFO_DISPLAY_NAME_INCREMENTAL.get(),
                        INFO_DESCRIPTION_INCREMENTAL.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the incremental base ID.
   */
  private static final TaskProperty PROPERTY_INCREMENTAL_BASE_ID =
       new TaskProperty(ATTR_INCREMENTAL_BASE_ID,
                        INFO_DISPLAY_NAME_INCREMENTAL_BASE_ID.get(),
                        INFO_DESCRIPTION_INCREMENTAL_BASE_ID.get(),
                        String.class, false, false, true);



  /**
   * The task property that will be used for the compress flag.
   */
  private static final TaskProperty PROPERTY_COMPRESS =
       new TaskProperty(ATTR_COMPRESS, INFO_DISPLAY_NAME_COMPRESS.get(),
                        INFO_DESCRIPTION_COMPRESS_BACKUP.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the encrypt flag.
   */
  private static final TaskProperty PROPERTY_ENCRYPT =
       new TaskProperty(ATTR_ENCRYPT, INFO_DISPLAY_NAME_ENCRYPT.get(),
                        INFO_DESCRIPTION_ENCRYPT_BACKUP.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the hash flag.
   */
  private static final TaskProperty PROPERTY_HASH =
       new TaskProperty(ATTR_HASH, INFO_DISPLAY_NAME_HASH.get(),
                        INFO_DESCRIPTION_HASH_BACKUP.get(), Boolean.class,
                        false, false, false);



  /**
   * The task property that will be used for the sign hash flag.
   */
  private static final TaskProperty PROPERTY_SIGN_HASH =
       new TaskProperty(ATTR_SIGN_HASH, INFO_DISPLAY_NAME_SIGN_HASH.get(),
                        INFO_DESCRIPTION_SIGN_HASH_BACKUP.get(), Boolean.class,
                        false, false, false);




  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8680226715226034105L;



  // Indicates whether to compress the backup.
  private final boolean compress;

  // Indicates whether to encrypt the backup.
  private final boolean encrypt;

  // Indicates whether to generate a hash of the backup.
  private final boolean hash;

  // Indicates whether to sign the backup hash.
  private final boolean signHash;

  // Indicates whether to perform an incremental backup.
  private final boolean incremental;

  // The backend IDs of the backends to back up.
  private final List<String> backendIDs;

  // The path to the directory in which to write the backup.
  private final String backupDirectory;

  // The backup ID to use for the backup.
  private final String backupID;

  // The backup ID of the backup to use as the base for the incremental backup.
  private final String incrementalBaseID;



  /**
   * Creates a new uninitialized backup task instance which should only be
   * used for obtaining general information about this task, including the task
   * name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public BackupTask()
  {
    compress          = false;
    encrypt           = false;
    hash              = false;
    signHash          = false;
    incremental       = false;
    backendIDs        = null;
    backupDirectory   = null;
    backupID          = null;
    incrementalBaseID = null;
  }




  /**
   * Creates a new backup task with the provided information.
   *
   * @param  taskID           The task ID to use for this task.  If it is
   *                          {@code null} then a UUID will be generated for use
   *                          as the task ID.
   * @param  backupDirectory  The path to the directory on the server into which
   *                          the backup should be written.  If a single backend
   *                          is to be archived, then this should be the path to
   *                          the specific backup directory for that backend.
   *                          If multiple backends are to be archived, then this
   *                          should be the parent of the directories for each
   *                          of the backends.  It must not be {@code null}.
   * @param  backendID        The backend ID of the backend to back up.  It may
   *                          be {@code null} if all supported backends should
   *                          be backed up.
   */
  public BackupTask(final String taskID, final String backupDirectory,
                    final String backendID)
  {
    this(taskID, backupDirectory,
         ((backendID == null) ? null : Arrays.asList(backendID)),
         null, false, null, false, false, false, false, null, null, null, null,
         null);
  }



  /**
   * Creates a new restore task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  backupDirectory         The path to the directory on the server
   *                                 into which the backup should be written.
   *                                 If a single backend is to be archived, then
   *                                 this should be the path to the specific
   *                                 backup directory for that backend.  If
   *                                 multiple backends are to be archived, then
   *                                 this should be the parent of the
   *                                 directories for each of the backends.  It
   *                                 must not be {@code null}.
   * @param  backendIDs              A list of the backend IDs of the backends
   *                                 to archive.  It may be {@code null} or
   *                                 empty if all supported backends should be
   *                                 archived.
   * @param  backupID                The backup ID to use for this backup.  It
   *                                 may be {@code null} to indicate that the
   *                                 server should generate the backup ID.
   * @param  incremental             Indicates whether to perform an incremental
   *                                 backup rather than a full backup.
   * @param  incrementalBaseID       The backup ID of the existing backup on
   *                                 which to base the incremental backup.  It
   *                                 may be {@code null} if this is not an
   *                                 incremental backup or if it should be based
   *                                 on the most recent backup.
   * @param  compress                Indicates whether the backup should be
   *                                 compressed.
   * @param  encrypt                 Indicates whether the backup should be
   *                                 encrypted.
   * @param  hash                    Indicates whether to generate a hash of the
   *                                 backup contents.
   * @param  signHash                Indicates whether to sign the hash of the
   *                                 backup contents.
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
  public BackupTask(final String taskID, final String backupDirectory,
                    final List<String> backendIDs, final String backupID,
                    final boolean incremental, final String incrementalBaseID,
                    final boolean compress, final boolean encrypt,
                    final boolean hash, final boolean signHash,
                    final Date scheduledStartTime,
                    final List<String> dependencyIDs,
                    final FailedDependencyAction failedDependencyAction,
                    final List<String> notifyOnCompletion,
                    final List<String> notifyOnError)
  {
    super(taskID, BACKUP_TASK_CLASS, scheduledStartTime,
          dependencyIDs, failedDependencyAction, notifyOnCompletion,
          notifyOnError);

    ensureNotNull(backupDirectory);

    this.backupDirectory   = backupDirectory;
    this.backupID          = backupID;
    this.incremental       = incremental;
    this.incrementalBaseID = incrementalBaseID;
    this.compress          = compress;
    this.encrypt           = encrypt;
    this.hash              = hash;
    this.signHash          = signHash;

    if (backendIDs == null)
    {
      this.backendIDs = Collections.emptyList();
    }
    else
    {
      this.backendIDs = Collections.unmodifiableList(backendIDs);
    }
  }



  /**
   * Creates a new backup task from the provided entry.
   *
   * @param  entry  The entry to use to create this backup task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a backup
   *                         task entry.
   */
  public BackupTask(final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the backup directory.  It must be present.
    backupDirectory = entry.getAttributeValue(ATTR_BACKUP_DIRECTORY);
    if (backupDirectory == null)
    {
      throw new TaskException(ERR_BACKUP_NO_BACKUP_DIRECTORY.get(
                                   getTaskEntryDN()));
    }


    // Get the set of backend IDs.  It may be absent.
    backendIDs = parseStringList(entry, ATTR_BACKEND_ID);


    // Get the backup ID.  It may be absent.
    backupID = entry.getAttributeValue(ATTR_BACKUP_ID);


    // Get the incremental flag.  It may be absent.
    incremental = parseBooleanValue(entry, ATTR_INCREMENTAL, false);


    // Get the incremental base ID.  It may be absent.
    incrementalBaseID = entry.getAttributeValue(ATTR_INCREMENTAL_BASE_ID);


    // Determine whether to compress the backup.  It may be absent.
    compress = parseBooleanValue(entry, ATTR_COMPRESS, false);


    // Determine whether to encrypt the backup.  It may be absent.
    encrypt = parseBooleanValue(entry, ATTR_ENCRYPT, false);


    // Determine whether to hash the backup.  It may be absent.
    hash = parseBooleanValue(entry, ATTR_HASH, false);


    // Determine whether to sign the hash.  It may be absent.
    signHash = parseBooleanValue(entry, ATTR_SIGN_HASH, false);
  }



  /**
   * Creates a new backup task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid backup task.
   */
  public BackupTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(BACKUP_TASK_CLASS, properties);

    boolean  c     = false;
    boolean  e     = false;
    boolean  h     = false;
    boolean  i     = false;
    boolean  s     = false;
    String   bDir  = null;
    String   bkID  = null;
    String   incID = null;
    String[] beIDs = StaticUtils.NO_STRINGS;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_BACKUP_DIRECTORY))
      {
        bDir = parseString(p, values, bDir);
      }
      else if (attrName.equalsIgnoreCase(ATTR_BACKEND_ID))
      {
        beIDs = parseStrings(p, values, beIDs);
      }
      else if (attrName.equalsIgnoreCase(ATTR_BACKUP_ID))
      {
        bkID = parseString(p, values, bkID);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCREMENTAL))
      {
        i = parseBoolean(p, values, i);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCREMENTAL_BASE_ID))
      {
        incID = parseString(p, values, incID);
      }
      else if (attrName.equalsIgnoreCase(ATTR_COMPRESS))
      {
        c = parseBoolean(p, values, c);
      }
      else if (attrName.equalsIgnoreCase(ATTR_ENCRYPT))
      {
        e = parseBoolean(p, values, e);
      }
      else if (attrName.equalsIgnoreCase(ATTR_HASH))
      {
        h = parseBoolean(p, values, h);
      }
      else if (attrName.equalsIgnoreCase(ATTR_SIGN_HASH))
      {
        s = parseBoolean(p, values, s);
      }
    }

    if (bDir == null)
    {
      throw new TaskException(ERR_BACKUP_NO_BACKUP_DIRECTORY.get(
                                   getTaskEntryDN()));
    }

    backupDirectory   = bDir;
    backendIDs        = Arrays.asList(beIDs);
    backupID          = bkID;
    incremental       = i;
    incrementalBaseID = incID;
    compress          = c;
    encrypt           = e;
    hash              = h;
    signHash          = s;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_BACKUP.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_BACKUP.get();
  }



  /**
   * Retrieves the path to the backup directory in which the backup files should
   * be written.  If a single backend is to be archived, then this will be the
   * directory in which the backup files are written.  If multiple backends are
   * to be archived, then this will be the parent of the directories containing
   * the backups for each backend.
   *
   * @return  The path to the backup directory in which the backup files should
   *          be written.
   */
  public String getBackupDirectory()
  {
    return backupDirectory;
  }



  /**
   * Indicates whether the server should back up all supported backends.
   *
   * @return  {@code true} if the server should back up all supported backends,
   *          or {@code false} if it should back up a specified backend or set
   *          of backends.
   */
  public boolean backupAll()
  {
    return backendIDs.isEmpty();
  }



  /**
   * Retrieves the set of backend IDs for the backends that should be archived.
   *
   * @return  The set of backend IDs for the backends that should be archived,
   *          or an empty list if the server should back up all supported
   *          backends.
   */
  public List<String> getBackendIDs()
  {
    return backendIDs;
  }



  /**
   * Retrieves the backup ID for the backup to generate.
   *
   * @return  The backup ID for the backup to generate, or {@code null} if the
   *          server should generate a backup ID.
   */
  public String getBackupID()
  {
    return backupID;
  }



  /**
   * Indicates whether the server should attempt to perform an incremental
   * backup rather than a full backup.
   *
   * @return  {@code true} if the server should attempt to perform an
   *          incremental backup, or {@code false} for a full backup.
   */
  public boolean incremental()
  {
    return incremental;
  }



  /**
   * Retrieves the backup ID of the existing backup on which the incremental
   * backup should be based.
   *
   * @return  The backup ID of the existing backup on which the incremental
   *          backup should be based, or {@code null} if it is not an
   *          incremental backup or the server should use the most recent
   *          backup available as the base for the new incremental backup.
   */
  public String getIncrementalBaseID()
  {
    return incrementalBaseID;
  }



  /**
   * Indicates whether the backup should be compressed.
   *
   * @return  {@code true} if the backup should be compressed, or {@code false}
   *          if not.
   */
  public boolean compress()
  {
    return compress;
  }



  /**
   * Indicates whether the backup should be encrypted.
   *
   * @return  {@code true} if the backup should be encrypted, or {@code false}
   *          if not.
   */
  public boolean encrypt()
  {
    return encrypt;
  }



  /**
   * Indicates whether the server should generate a hash of the backup.
   *
   * @return  {@code true} if the server should generate a hash of the backup,
   *          or {@code false} if not.
   */
  public boolean hash()
  {
    return hash;
  }



  /**
   * Indicates whether the server should sign the backup hash.
   *
   * @return  {@code true} if the server should sign the backup hash, or
   *          {@code false} if not.
   */
  public boolean signHash()
  {
    return signHash;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_BACKUP_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    final ArrayList<Attribute> attrs = new ArrayList<Attribute>(9);

    attrs.add(new Attribute(ATTR_BACKUP_DIRECTORY, backupDirectory));
    attrs.add(new Attribute(ATTR_INCREMENTAL,  String.valueOf(incremental)));
    attrs.add(new Attribute(ATTR_COMPRESS, String.valueOf(compress)));
    attrs.add(new Attribute(ATTR_ENCRYPT, String.valueOf(encrypt)));
    attrs.add(new Attribute(ATTR_HASH, String.valueOf(hash)));
    attrs.add(new Attribute(ATTR_SIGN_HASH, String.valueOf(signHash)));

    if (backendIDs.isEmpty())
    {
      attrs.add(new Attribute(ATTR_BACKUP_ALL, "true"));
    }
    else
    {
      attrs.add(new Attribute(ATTR_BACKEND_ID, backendIDs));
    }

    if (backupID != null)
    {
      attrs.add(new Attribute(ATTR_BACKUP_ID, backupID));
    }

    if (incrementalBaseID != null)
    {
      attrs.add(new Attribute(ATTR_INCREMENTAL_BASE_ID, incrementalBaseID));
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
         PROPERTY_BACKEND_ID,
         PROPERTY_BACKUP_ID,
         PROPERTY_INCREMENTAL,
         PROPERTY_INCREMENTAL_BASE_ID,
         PROPERTY_COMPRESS,
         PROPERTY_ENCRYPT,
         PROPERTY_HASH,
         PROPERTY_SIGN_HASH);

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

    props.put(PROPERTY_BACKEND_ID,
              Collections.<Object>unmodifiableList(backendIDs));

    if (backupID == null)
    {
      props.put(PROPERTY_BACKUP_ID, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_BACKUP_ID,
                Collections.<Object>unmodifiableList(Arrays.asList(backupID)));
    }

    props.put(PROPERTY_INCREMENTAL,
              Collections.<Object>unmodifiableList(Arrays.asList(incremental)));

    if (incrementalBaseID == null)
    {
      props.put(PROPERTY_INCREMENTAL_BASE_ID, Collections.emptyList());
    }
    else
    {
      props.put(PROPERTY_INCREMENTAL_BASE_ID,
                Collections.<Object>unmodifiableList(Arrays.asList(
                     incrementalBaseID)));
    }

    props.put(PROPERTY_COMPRESS,
              Collections.<Object>unmodifiableList(Arrays.asList(compress)));

    props.put(PROPERTY_ENCRYPT,
              Collections.<Object>unmodifiableList(Arrays.asList(encrypt)));

    props.put(PROPERTY_HASH,
              Collections.<Object>unmodifiableList(Arrays.asList(hash)));

    props.put(PROPERTY_SIGN_HASH,
              Collections.<Object>unmodifiableList(Arrays.asList(signHash)));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
