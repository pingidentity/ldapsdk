/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.args.DurationArgument;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to identify files
 * in a specified directory that match a given pattern, and delete any of those
 * files that are outside of a provided set of retention criteria.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The files to examine are identified by a combination of three items:
 * <UL>
 *   <LI>A target directory.  This is simply the path to the directory that
 *       contains the files to examine.</LI>
 *   <LI>A filename pattern.  This is a string that will be used to identify
 *       the files of interest in the target directory.  The pattern may contain
 *       zero or more (non-consecutive) asterisks to use as wildcards that match
 *       zero or more characters, and it may contain at most one occurrence of
 *       the token "${timestamp}" (without the quotation marks) that is a
 *       placeholder for a timestamp that indicates when the file was written or
 *       the age of the data in that file.  For example, the filename pattern
 *       "*-${timestamp}.log" will match any file in the target directory that
 *       ends with a dash, a timestamp, and an extension of ".log".</LI>
 *   <LI>A timestamp format.  This specifies the format that will be used for
 *       the value that matches the "${timestamp}" token in the filename
 *       pattern.  See the {@link FileRetentionTaskTimestampFormat} enum for the
 *       set of defined timestamp formats.</LI>
 * </UL>
 * <BR>
 * The types of retention criteria include:
 * <UL>
 *   <LI>A retain count, which specifies the minimum number of files to retain.
 *       For example, if there is a retain count of five, and the target
 *       directory contains ten files that match the filename pattern, the task
 *       will always keep at least the five most recent files, while the five
 *       oldest files will be candidates for removal.</LI>
 *   <LI>A retain age, which specifies the minimum age of the files to retain.
 *       If the filename pattern includes a timestamp, then the age of the file
 *       will be determined using that timestamp.  If the filename pattern does
 *       not contain a timestamp, then the age of the file will be determined
 *       from the file's create time attribute (if available) or last modified
 *       time.  The task will always keep all files whose age is less than or
 *       equal to the retain age, while files older than the retain age will be
 *       candidates for removal.</LI>
 *   <LI>An aggregate retain size, which specifies combined minimum amount of
 *       disk space that should be consumed by the files that should be
 *       retained.  For example, if the task is configured with an aggregate
 *       retain size of 500 megabytes and the files to examine are all 75
 *       megabytes each, then the task will keep at least the seven most recent
 *       files (because 500/75 = 6.7, and the task will always round up to the
 *       next whole number), and any older files in the same directory that
 *       match the pattern will be candidates for removal.
 * </UL>
 * <BR>
 * The task must be configured with at least one of the three types of retention
 * criteria, but it may combine any two or all three of them.  If a task is
 * configured with multiple types of retention criteria, then a file will only
 * be a candidate for removal if it is outside of all of the retention criteria.
 * For example, if the task is configured with a retain count of 5 and a retain
 * age of 1 week, then the task may retain more than five files if there are
 * more than five files that are less than a week old, and it may retain files
 * that are more than a week old if there are fewer than five files within that
 * age.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FileRetentionTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the file
   * retention task.
   */
  @NotNull static final String FILE_RETENTION_TASK_CLASS =
       "com.unboundid.directory.server.tasks.FileRetentionTask";



  /**
   * The name of the attribute that is used to specify the path to the directory
   * containing the files to delete.
   */
  @NotNull private static final String ATTR_TARGET_DIRECTORY =
       "ds-task-file-retention-target-directory";



  /**
   * The name of the attribute that is used to specify the filename pattern that
   * is used to identify the files to examine.
   */
  @NotNull private static final String ATTR_FILENAME_PATTERN =
       "ds-task-file-retention-filename-pattern";



  /**
   * The name of the attribute that is used to specify the format to use for
   * timestamp values in the filename pattern.
   */
  @NotNull private static final String ATTR_TIMESTAMP_FORMAT =
       "ds-task-file-retention-timestamp-format";



  /**
   * The name of the attribute that is used to specify the minimum number of
   * files to retain.
   */
  @NotNull private static final String ATTR_RETAIN_FILE_COUNT =
       "ds-task-file-retention-retain-file-count";



  /**
   * The name of the attribute that is used to specify the minimum age of
   * files to retain.
   */
  @NotNull private static final String ATTR_RETAIN_FILE_AGE =
       "ds-task-file-retention-retain-file-age";



  /**
   * The name of the attribute that is used to specify the minimum aggregate
   * size, in bytes, of files to retain.
   */
  @NotNull private static final String ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES =
       "ds-task-file-retention-retain-aggregate-file-size-bytes";



  /**
   * The name of the object class used in file retention task entries.
   */
  @NotNull private static final String OC_FILE_RETENTION_TASK =
       "ds-task-file-retention";



  /**
   * The task property that will be used for the target directory.
   */
  @NotNull private static final TaskProperty PROPERTY_TARGET_DIRECTORY =
     new TaskProperty(ATTR_TARGET_DIRECTORY,
          INFO_FILE_RETENTION_DISPLAY_NAME_TARGET_DIRECTORY.get(),
          INFO_FILE_RETENTION_DESCRIPTION_TARGET_DIRECTORY.get(), String.class,
          true, false, false);



  /**
   * The task property that will be used for the filename pattern.
   */
  @NotNull private static final TaskProperty PROPERTY_FILENAME_PATTERN =
     new TaskProperty(ATTR_FILENAME_PATTERN,
          INFO_FILE_RETENTION_DISPLAY_NAME_FILENAME_PATTERN.get(),
          INFO_FILE_RETENTION_DESCRIPTION_FILENAME_PATTERN.get(), String.class,
          true, false, false);



  /**
   * The task property that will be used for the timestamp format.
   */
  @NotNull private static final TaskProperty PROPERTY_TIMESTAMP_FORMAT =
     new TaskProperty(ATTR_TIMESTAMP_FORMAT,
          INFO_FILE_RETENTION_DISPLAY_NAME_TIMESTAMP_FORMAT.get(),
          INFO_FILE_RETENTION_DESCRIPTION_TIMESTAMP_FORMAT.get(), String.class,
          true, false, false,
          new String[]
          {
            FileRetentionTaskTimestampFormat.
                 GENERALIZED_TIME_UTC_WITH_MILLISECONDS.name(),
            FileRetentionTaskTimestampFormat.
                 GENERALIZED_TIME_UTC_WITH_SECONDS.name(),
            FileRetentionTaskTimestampFormat.
                 GENERALIZED_TIME_UTC_WITH_MINUTES.name(),
            FileRetentionTaskTimestampFormat.
                 LOCAL_TIME_WITH_MILLISECONDS.name(),
            FileRetentionTaskTimestampFormat.LOCAL_TIME_WITH_SECONDS.name(),
            FileRetentionTaskTimestampFormat.LOCAL_TIME_WITH_MINUTES.name(),
            FileRetentionTaskTimestampFormat.LOCAL_DATE.name()
          });



  /**
   * The task property that will be used for the file retention count.
   */
  @NotNull private static final TaskProperty PROPERTY_RETAIN_FILE_COUNT =
     new TaskProperty(ATTR_RETAIN_FILE_COUNT,
          INFO_FILE_RETENTION_DISPLAY_NAME_RETAIN_COUNT.get(),
          INFO_FILE_RETENTION_DESCRIPTION_RETAIN_COUNT.get(), Long.class,
          false, false, false);



  /**
   * The task property that will be used for the file retention age.
   */
  @NotNull private static final TaskProperty PROPERTY_RETAIN_FILE_AGE_MILLIS =
     new TaskProperty(ATTR_RETAIN_FILE_AGE,
          INFO_FILE_RETENTION_DISPLAY_NAME_RETAIN_AGE.get(),
          INFO_FILE_RETENTION_DESCRIPTION_RETAIN_AGE.get(), Long.class,
          false, false, false);



  /**
   * The task property that will be used for the file retention size.
   */
  @NotNull private static final TaskProperty
       PROPERTY_RETAIN_AGGREGATE_FILE_SIZE_BYTES = new TaskProperty(
            ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES,
            INFO_FILE_RETENTION_DISPLAY_NAME_RETAIN_SIZE.get(),
            INFO_FILE_RETENTION_DESCRIPTION_RETAIN_SIZE.get(), Long.class,
            false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7401251158315611295L;



  // The format for the timestamp that may be used in the filename pattern.
  @NotNull private final FileRetentionTaskTimestampFormat timestampFormat;

  // The file retention count.
  @Nullable private final Integer retainFileCount;

  // The file retention aggregate size in bytes.
  @Nullable private final Long retainAggregateFileSizeBytes;

  // The file retention age in milliseconds.
  @Nullable private final Long retainFileAgeMillis;

  // The pattern that identifies the files to examine.
  @NotNull private final String filenamePattern;

  // The path to the directory containing the files to examine.
  @NotNull private final String targetDirectory;



  /**
   * Creates a new, uninitialized file retention task instance that should only
   * be used for obtaining general information about this task, including the
   * task name, description, and supported properties.  Attempts to use a task
   * created with this constructor for any other reason will likely fail.
   */
  public FileRetentionTask()
  {
    targetDirectory = null;
    filenamePattern = null;
    timestampFormat = null;
    retainFileCount = null;
    retainFileAgeMillis = null;
    retainAggregateFileSizeBytes = null;
  }



  /**
   * Creates a new file retention task with the provided information.
   *
   * @param  targetDirectory
   *              The path to the directory containing the files to examine.
   *              This must be provided, and the target directory must exist on
   *              the server filesystem.
   * @param  filenamePattern
   *              A pattern that identifies the files to examine.  The pattern
   *              may include zero or more (non-consecutive) asterisks that act
   *              as wildcards and match zero or more characters.  The pattern
   *              may also contain at most one occurrence of the "${timestamp}"
   *              token, which indicates that the filename includes a timestamp
   *              with the format specified in the {@code timestampFormat}
   *              argument.  This must not be {@code null} or empty.
   * @param  timestampFormat
   *              The expected format for the timestamp that may appear in the
   *              filename pattern.  This must not be {@code null}, even if the
   *              filename pattern does not contain a "${timestamp}" token.
   * @param  retainFileCount
   *              The minimum number of the most recent files that should be
   *              retained.  This may be {@code null} if only age-based or
   *              size-based retention criteria should be used.  At least one of
   *              the {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then it
   *              must be greater than or equal to zero.
   * @param  retainFileAgeMillis
   *              The minimum age, in milliseconds, for files that should be
   *              retained.  This may be {@code null} if only count-based or
   *              size-based retention criteria should be used.  At least one of
   *              the {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then
   *              it must be greater than zero.
   * @param  retainAggregateFileSizeBytes
   *              The minimum amount of disk space, in bytes, that should be
   *              consumed by the files to be retained.  This may be
   *              {@code null} if only count-based or age-based retention
   *              criteria should be used.  At least one of the
   *              {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then it
   *              must be greater than zero.
   */
  public FileRetentionTask(@NotNull final String targetDirectory,
              @NotNull final String filenamePattern,
              @NotNull final FileRetentionTaskTimestampFormat timestampFormat,
              @Nullable final Integer retainFileCount,
              @Nullable final Long retainFileAgeMillis,
              @Nullable final Long retainAggregateFileSizeBytes)
  {
    this(null, targetDirectory, filenamePattern, timestampFormat,
         retainFileCount, retainFileAgeMillis, retainAggregateFileSizeBytes,
         null, null, null, null, null, null, null, null, null, null);
  }



  /**
   * Creates a new file retention task with the provided information.
   *
   * @param  taskID
   *              The task ID to use for this task.  If it is {@code null} then
   *              a UUID will be generated for use as the task ID.
   * @param  targetDirectory
   *              The path to the directory containing the files to examine.
   *              This must be provided, and the target directory must exist on
   *              the server filesystem.
   * @param  filenamePattern
   *              A pattern that identifies the files to examine.  The pattern
   *              may include zero or more (non-consecutive) asterisks that act
   *              as wildcards and match zero or more characters.  The pattern
   *              may also contain at most one occurrence of the "${timestamp}"
   *              token, which indicates that the filename includes a timestamp
   *              with the format specified in the {@code timestampFormat}
   *              argument.  This must not be {@code null} or empty.
   * @param  timestampFormat
   *              The expected format for the timestamp that may appear in the
   *              filename pattern.  This must not be {@code null}, even if the
   *              filename pattern does not contain a "${timestamp}" token.
   * @param  retainFileCount
   *              The minimum number of the most recent files that should be
   *              retained.  This may be {@code null} if only age-based or
   *              size-based retention criteria should be used.  At least one of
   *              the {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then it
   *              must be greater than or equal to zero.
   * @param  retainFileAgeMillis
   *              The minimum age, in milliseconds, for files that should be
   *              retained.  This may be {@code null} if only count-based or
   *              size-based retention criteria should be used.  At least one of
   *              the {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then
   *              it must be greater than zero.
   * @param  retainAggregateFileSizeBytes
   *              The minimum amount of disk space, in bytes, that should be
   *              consumed by the files to be retained.  This may be
   *              {@code null} if only count-based or age-based retention
   *              criteria should be used.  At least one of the
   *              {@code retainFileCount}, {@code retainFileAgeMillis}, and
   *              {@code retainAggregateFileSizeBytes} values must be
   *              non-{@code null}.  If this value is non-{@code null}, then it
   *              must be greater than zero.
   * @param  scheduledStartTime
   *              The time that this task should start running.
   * @param  dependencyIDs
   *              The list of task IDs that will be required to complete before
   *              this task will be eligible to start.
   * @param  failedDependencyAction
   *              Indicates what action should be taken if any of the
   *              dependencies for this task do not complete successfully.
   * @param  notifyOnStart
   *              The list of e-mail addresses of individuals that should be
   *              notified when this task starts.
   * @param  notifyOnCompletion
   *              The list of e-mail addresses of individuals that should be
   *              notified when this task completes.
   * @param  notifyOnSuccess
   *              The list of e-mail addresses of individuals that should be
   *              notified if this task completes successfully.
   * @param  notifyOnError
   *              The list of e-mail addresses of individuals that should be
   *              notified if this task does not complete successfully.
   * @param  alertOnStart
   *              Indicates whether the server should send an alert notification
   *              when this task starts.
   * @param  alertOnSuccess
   *              Indicates whether the server should send an alert notification
   *              if this task completes successfully.
   * @param  alertOnError
   *              Indicates whether the server should send an alert notification
   *              if this task fails to complete successfully.
   */
  public FileRetentionTask(@Nullable final String taskID,
              @NotNull final String targetDirectory,
              @NotNull final String filenamePattern,
              @NotNull final FileRetentionTaskTimestampFormat timestampFormat,
              @Nullable final Integer retainFileCount,
              @Nullable final Long retainFileAgeMillis,
              @Nullable final Long retainAggregateFileSizeBytes,
              @Nullable final Date scheduledStartTime,
              @Nullable final List<String> dependencyIDs,
              @Nullable final FailedDependencyAction failedDependencyAction,
              @Nullable final List<String> notifyOnStart,
              @Nullable final List<String> notifyOnCompletion,
              @Nullable final List<String> notifyOnSuccess,
              @Nullable final List<String> notifyOnError,
              @Nullable final Boolean alertOnStart,
              @Nullable final Boolean alertOnSuccess,
              @Nullable final Boolean alertOnError)
  {
    super(taskID, FILE_RETENTION_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    Validator.ensureNotNullOrEmpty(targetDirectory,
         "FileRetentionTask.targetDirectory must not be null or empty");
    Validator.ensureNotNullOrEmpty(filenamePattern,
         "FileRetentionTask.filenamePattern must not be null or empty");
    Validator.ensureNotNullWithMessage(timestampFormat,
         "FileRetentionTask.timestampFormat must not be null");

    Validator.ensureTrue(
         ((retainFileCount != null) || (retainFileAgeMillis != null) ||
              (retainAggregateFileSizeBytes != null)),
         "At least one of retainFileCount, retainFileAgeMillis, and " +
              "retainAggregateFileSizeBytes must be non-null");

    Validator.ensureTrue(
         ((retainFileCount == null) || (retainFileCount >= 0)),
         "FileRetentionTask.retainFileCount must not be negative");
    Validator.ensureTrue(
         ((retainFileAgeMillis == null) || (retainFileAgeMillis > 0L)),
         "FileRetentionTask.retainFileAgeMillis must not be negative or zero");
    Validator.ensureTrue(
         ((retainAggregateFileSizeBytes == null) ||
              (retainAggregateFileSizeBytes > 0L)),
         "FileRetentionTask.retainAggregateFileSizeBytes must not be " +
              "negative or zero");

    this.targetDirectory = targetDirectory;
    this.filenamePattern = filenamePattern;
    this.timestampFormat = timestampFormat;
    this.retainFileCount = retainFileCount;
    this.retainFileAgeMillis = retainFileAgeMillis;
    this.retainAggregateFileSizeBytes = retainAggregateFileSizeBytes;
  }



  /**
   * Creates a new file retention task from the provided entry.
   *
   * @param  entry  The entry to use to create this file retention task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a file
   *                         retention task entry.
   */
  public FileRetentionTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    // Get the path to the target directory.  It must not be null or empty.
    targetDirectory = entry.getAttributeValue(ATTR_TARGET_DIRECTORY);
    if ((targetDirectory == null) || targetDirectory.isEmpty())
    {
      throw new TaskException(
           ERR_FILE_RETENTION_ENTRY_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_TARGET_DIRECTORY));
    }


    // Get the path to the filename pattern.  It must not be null or empty.
    filenamePattern = entry.getAttributeValue(ATTR_FILENAME_PATTERN);
    if ((filenamePattern == null) || filenamePattern.isEmpty())
    {
      throw new TaskException(
           ERR_FILE_RETENTION_ENTRY_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_FILENAME_PATTERN));
    }


    // Get the timestamp format.  It must not be null, and must be a valid
    // format.
    final String timestampFormatName =
         entry.getAttributeValue(ATTR_TIMESTAMP_FORMAT);
    if (timestampFormatName == null)
    {
      throw new TaskException(
           ERR_FILE_RETENTION_ENTRY_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_TIMESTAMP_FORMAT));
    }

    timestampFormat =
         FileRetentionTaskTimestampFormat.forName(timestampFormatName);
    if (timestampFormat == null)
    {
      final StringBuilder validFormats = new StringBuilder();
      for (final FileRetentionTaskTimestampFormat f :
           FileRetentionTaskTimestampFormat.values())
      {
        if (validFormats.length() > 0)
        {
          validFormats.append(", ");
        }

        validFormats.append(f.name());
      }

      throw new TaskException(
           ERR_FILE_RETENTION_ENTRY_INVALID_TIMESTAMP_FORMAT.get(
                entry.getDN(), timestampFormatName, validFormats.toString()));
    }


    // Get the retain file count.  If it is non-null, then it must also be
    // non-negative.
    final String retainFileCountString =
         entry.getAttributeValue(ATTR_RETAIN_FILE_COUNT);
    if (retainFileCountString == null)
    {
      retainFileCount = null;
    }
    else
    {
      try
      {
        retainFileCount = Integer.parseInt(retainFileCountString);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new TaskException(
             ERR_FILE_RETENTION_ENTRY_INVALID_RETAIN_COUNT.get(
                  entry.getDN(), retainFileCountString),
             e);
      }

      if (retainFileCount < 0)
      {
        throw new TaskException(
             ERR_FILE_RETENTION_ENTRY_INVALID_RETAIN_COUNT.get(
                  entry.getDN(), retainFileCountString));
      }
    }


    // Get the retain file age in milliseconds.
    final String retainFileAgeString =
         entry.getAttributeValue(ATTR_RETAIN_FILE_AGE);
    if (retainFileAgeString == null)
    {
      retainFileAgeMillis = null;
    }
    else
    {
      try
      {
        retainFileAgeMillis = DurationArgument.parseDuration(
             retainFileAgeString, TimeUnit.MILLISECONDS);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new TaskException(
             ERR_FILE_RETENTION_ENTRY_INVALID_RETAIN_AGE.get(
                  entry.getDN(), retainFileAgeString,
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // Get the retain aggregate file size in bytes.  If it is non-null, then it
    // must also be positive.
    final String retainAggregateFileSizeBytesString =
         entry.getAttributeValue(ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES);
    if (retainAggregateFileSizeBytesString == null)
    {
      retainAggregateFileSizeBytes = null;
    }
    else
    {
      try
      {
        retainAggregateFileSizeBytes =
             Long.parseLong(retainAggregateFileSizeBytesString);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new TaskException(
             ERR_FILE_RETENTION_ENTRY_INVALID_RETAIN_SIZE.get(
                  entry.getDN(), retainAggregateFileSizeBytesString),
             e);
      }

      if (retainAggregateFileSizeBytes <= 0)
      {
        throw new TaskException(
             ERR_FILE_RETENTION_ENTRY_INVALID_RETAIN_SIZE.get(
                  entry.getDN(), retainAggregateFileSizeBytesString));
      }
    }

    if ((retainFileCount == null) && (retainFileAgeMillis == null) &&
       (retainAggregateFileSizeBytes == null))
    {
      throw new TaskException(
           ERR_FILE_RETENTION_ENTRY_MISSING_RETENTION_CRITERIA.get(
                entry.getDN(), ATTR_RETAIN_FILE_COUNT, ATTR_RETAIN_FILE_AGE,
                ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES));
    }
  }



  /**
   * Creates a new file retention task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid file retention task.
   */
  public FileRetentionTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(FILE_RETENTION_TASK_CLASS, properties);

    String directory = null;
    String pattern = null;
    FileRetentionTaskTimestampFormat format = null;
    Long count = null;
    Long age = null;
    Long size = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = StaticUtils.toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();
      switch (attrName)
      {
        case ATTR_TARGET_DIRECTORY:
          directory = parseString(p, values, null);
          break;
        case ATTR_FILENAME_PATTERN:
          pattern = parseString(p, values, null);
          break;
        case ATTR_TIMESTAMP_FORMAT:
          final String formatName = parseString(p, values, null);
          format = FileRetentionTaskTimestampFormat.forName(formatName);
          break;
        case ATTR_RETAIN_FILE_COUNT:
          count = parseLong(p, values, null);
          break;
        case ATTR_RETAIN_FILE_AGE:
          age = parseLong(p, values, null);
          break;
        case ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES:
          size = parseLong(p, values, null);
          break;
      }
    }

    targetDirectory = directory;
    filenamePattern = pattern;
    timestampFormat = format;
    retainFileAgeMillis = age;
    retainAggregateFileSizeBytes = size;

    if (count == null)
    {
      retainFileCount = null;
    }
    else
    {
      retainFileCount = count.intValue();
    }

    if ((targetDirectory == null) || targetDirectory.isEmpty())
    {
      throw new TaskException(ERR_FILE_RETENTION_MISSING_REQUIRED_PROPERTY.get(
           ATTR_TARGET_DIRECTORY));
    }

    if ((filenamePattern == null) || filenamePattern.isEmpty())
    {
      throw new TaskException(ERR_FILE_RETENTION_MISSING_REQUIRED_PROPERTY.get(
           ATTR_FILENAME_PATTERN));
    }

    if (timestampFormat == null)
    {
      throw new TaskException(ERR_FILE_RETENTION_MISSING_REQUIRED_PROPERTY.get(
           ATTR_TIMESTAMP_FORMAT));
    }

    if ((retainFileCount == null) && (retainFileAgeMillis == null) &&
         (retainAggregateFileSizeBytes == null))
    {
      throw new TaskException(ERR_FILE_RETENTION_MISSING_RETENTION_PROPERTY.get(
           ATTR_RETAIN_FILE_COUNT, ATTR_RETAIN_FILE_AGE,
           ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_FILE_RETENTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_FILE_RETENTION.get();
  }



  /**
   * Retrieves the path to the directory (on the server filesystem) containing
   * the files to examine.
   *
   * @return  The path to the directory (on the server filesystem) containing
   *          the files to examine.
   */
  @NotNull()
  public String getTargetDirectory()
  {
    return targetDirectory;
  }



  /**
   * Retrieves the filename pattern that the task should use to identify which
   * files to examine.
   *
   * @return  The filename pattern that the task should use to identify which
   *          files to examine.
   */
  @NotNull()
  public String getFilenamePattern()
  {
    return filenamePattern;
  }



  /**
   * Retrieves the format to use to interpret the timestamp element in the
   * filename pattern.
   *
   * @return  The format to use to interpret the timestamp element in the
   *          filename pattern.
   */
  @NotNull()
  public FileRetentionTaskTimestampFormat getTimestampFormat()
  {
    return timestampFormat;
  }



  /**
   * Retrieves the minimum number of files to retain, if defined.
   *
   * @return  The minimum number of files to retain, or {@code null} if there
   *          is no count-based retention criteria.
   */
  @Nullable()
  public Integer getRetainFileCount()
  {
    return retainFileCount;
  }



  /**
   * Retrieves the minimum age (in milliseconds) of files to retain, if defined.
   *
   * @return  The minimum age (in milliseconds) of files to retain, or
   *          {@code null} if there is no age-based retention criteria.
   */
  @Nullable()
  public Long getRetainFileAgeMillis()
  {
    return retainFileAgeMillis;
  }



  /**
   * Retrieves the minimum aggregate size (in bytes) of files to retain, if
   * defined.
   *
   * @return  The minimum aggregate size (in bytes) of files to retain, or
   *          {@code null} if there is no size-based retention criteria.
   */
  @Nullable()
  public Long getRetainAggregateFileSizeBytes()
  {
    return retainAggregateFileSizeBytes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_FILE_RETENTION_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final LinkedList<Attribute> attrList = new LinkedList<>();
    attrList.add(new Attribute(ATTR_TARGET_DIRECTORY, targetDirectory));
    attrList.add(new Attribute(ATTR_FILENAME_PATTERN, filenamePattern));
    attrList.add(new Attribute(ATTR_TIMESTAMP_FORMAT, timestampFormat.name()));

    if (retainFileCount != null)
    {
      attrList.add(new Attribute(ATTR_RETAIN_FILE_COUNT,
           String.valueOf(retainFileCount)));
    }

    if (retainFileAgeMillis != null)
    {
      final long retainFileAgeNanos = retainFileAgeMillis * 1_000_000L;
      final String retainFileAgeString =
           DurationArgument.nanosToDuration(retainFileAgeNanos);
      attrList.add(new Attribute(ATTR_RETAIN_FILE_AGE, retainFileAgeString));
    }

    if (retainAggregateFileSizeBytes != null)
    {
      attrList.add(new Attribute(ATTR_RETAIN_AGGREGATE_FILE_SIZE_BYTES,
           String.valueOf(retainAggregateFileSizeBytes)));
    }

    return attrList;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(
         PROPERTY_TARGET_DIRECTORY,
         PROPERTY_FILENAME_PATTERN,
         PROPERTY_TIMESTAMP_FORMAT,
         PROPERTY_RETAIN_FILE_COUNT,
         PROPERTY_RETAIN_FILE_AGE_MILLIS,
         PROPERTY_RETAIN_AGGREGATE_FILE_SIZE_BYTES));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty, List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(6));

    props.put(PROPERTY_TARGET_DIRECTORY,
         Collections.<Object>singletonList(targetDirectory));
    props.put(PROPERTY_FILENAME_PATTERN,
         Collections.<Object>singletonList(filenamePattern));
    props.put(PROPERTY_TIMESTAMP_FORMAT,
         Collections.<Object>singletonList(timestampFormat.name()));

    if (retainFileCount != null)
    {
      props.put(PROPERTY_RETAIN_FILE_COUNT,
           Collections.<Object>singletonList(retainFileCount.longValue()));
    }

    if (retainFileAgeMillis != null)
    {
      props.put(PROPERTY_RETAIN_FILE_AGE_MILLIS,
           Collections.<Object>singletonList(retainFileAgeMillis));
    }

    if (retainAggregateFileSizeBytes != null)
    {
      props.put(PROPERTY_RETAIN_AGGREGATE_FILE_SIZE_BYTES,
           Collections.<Object>singletonList(retainAggregateFileSizeBytes));
    }

    return Collections.unmodifiableMap(props);
  }
}
