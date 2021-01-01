/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.DurationArgument;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to cause it to
 * generate a server profile in a specified location on the server filesystem.
 * The profile may be created in a directory structure or packaged in a zip
 * file.
\ * <BR>
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
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>
 *     The path on the server filesystem to the location in which the generated
 *     server profile should be written.  If the profile is to be packaged into
 *     a zip file, then this may either be the path to the zip file to create
 *     (which must not yet exist, although its parent directory must exist) or
 *     the path to the directory (which must already exist) in which the zip
 *     file will be created with a server-generated name.  If the profile is
 *     not to be packaged into a zip file, then this must be the path to the
 *     directory in which the profile will be written, and either that
 *     directory must exist and be empty or it must not exist but its parent
 *     directory must exist.  In either case, the path provided may be an
 *     absolute path, or it may be a relative path that is interpreted as
 *     relative to the instance root.  If this property is not provided, then
 *     the zip file or profile directory will be created in the instance root
 *     with a server-generated name.
 *   </LI>
 *   <LI>
 *     An optional set of additional paths to files or directories within the
 *     instance root that should be included in the server profile.  These may
 *     be specified as either absolute paths or relative paths that will be
 *     interpreted as relative to the instance root, but the paths must refer
 *     to files or directories that exist beneath the instance root.  If this is
 *     omitted, then no additional include paths will be used.
 *   </LI>
 *   <LI>
 *     A flag indicating whether the generated server profile should be packaged
 *     into a zip file.  If this is omitted, then the server will determine
 *     whether to package the profile into a zip file.
 *   </LI>
 *   <LI>
 *     Optional properties indicating the number and/or age of previous profile
 *     zip files to retain.  These options may only be used if the profile is
 *     to be packaged into a zip file, and if the name of the zip file will be
 *     generated by the server.
 *   </LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenerateServerProfileTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the generate
   * server profile task.
   */
  @NotNull static final String GENERATE_SERVER_PROFILE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.GenerateServerProfileTask";



  /**
   * The name of the attribute used to specify additional paths within the
   * instance root that should be included in the generated server profile.
   */
  @NotNull private static final String ATTR_INCLUDE_PATH =
       "ds-task-generate-server-profile-include-path";



  /**
   * The name of the attribute used to specify the path to which the generated
   * profile should be written.
   */
  @NotNull private static final String ATTR_PROFILE_ROOT =
       "ds-task-generate-server-profile-root";



  /**
   * The name of the attribute used to specify the age of previous profile zip
   * files to retain.
   */
  @NotNull private static final String ATTR_RETAIN_AGE =
       "ds-task-generate-server-profile-retain-age";



  /**
   * The name of the attribute used to specify the number of previous profile
   * zip files to retain.
   */
  @NotNull private static final String ATTR_RETAIN_COUNT =
       "ds-task-generate-server-profile-retain-count";



  /**
   * The name of the attribute used to indicate whether the generated server
   * profile should be packaged into a zip file.
   */
  @NotNull private static final String ATTR_ZIP =
       "ds-task-generate-server-profile-zip";



  /**
   * The name of the object class used in generate server profile task entries.
   */
  @NotNull private static final String OC_GENERATE_SERVER_PROFILE_TASK =
       "ds-task-generate-server-profile";



  /**
   * The task property that will be used for the optional include paths.
   */
  @NotNull private static final TaskProperty PROPERTY_INCLUDE_PATH =
       new TaskProperty(ATTR_INCLUDE_PATH,
            INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_INCLUDE_PATH.get(),
            INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_INCLUDE_PATH.get(),
            String.class, false, true, false);



  /**
   * The task property that will be used for the profile root.
   */
  @NotNull private static final TaskProperty PROPERTY_PROFILE_ROOT =
       new TaskProperty(ATTR_PROFILE_ROOT,
            INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_PROFILE_ROOT.get(),
            INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_PROFILE_ROOT.get(),
            String.class, false, false, false);



  /**
   * The task property that will be used for the retain age.
   */
  @NotNull static final TaskProperty PROPERTY_RETAIN_AGE = new TaskProperty(
       ATTR_RETAIN_AGE,
       INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_RETAIN_AGE.get(),
       INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_RETAIN_AGE.get(),
       String.class, false, false, false);



  /**
   * The task property that will be used for the retain count.
   */
  @NotNull private static final TaskProperty PROPERTY_RETAIN_COUNT =
       new TaskProperty(ATTR_RETAIN_COUNT,
            INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_RETAIN_COUNT.get(),
            INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_RETAIN_COUNT.get(),
            Long.class, false, false, false);



  /**
   * The task property that will be used to indicate whether to package the
   * server profile in a zip file.
   */
  @NotNull private static final TaskProperty PROPERTY_ZIP =
       new TaskProperty(ATTR_ZIP,
            INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_ZIP.get(),
            INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_ZIP.get(),
            Boolean.class, false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long  serialVersionUID = -6569877503912024942L;



  // Indicates whether to package the generated server profile into a zip file.
  @Nullable private final Boolean zipProfile;

  // The minimum number of previous profile zip files to retain.
  @Nullable private final Integer retainCount;

  // The list of additional paths within the instance root that should be
  // included in the generated server profile.
  @NotNull private final List<String> includePaths;

  // The path to the zip file or directory to which the generated server profile
  // will be written.
  @Nullable private final String profileRoot;

  // The minimum age of previous profile zip files to retain.
  @Nullable private final String retainAge;



  /**
   * Creates a new uninitialized generate server profile task instance that
   * should only be used for obtaining general information about this task,
   * including the task name, description, and supported properties.  Attempts
   * to use a task created with this constructor for any other reason will
   * likely fail.
   */
  public GenerateServerProfileTask()
  {
    super();

    zipProfile = null;
    includePaths = null;
    profileRoot = null;
    retainCount = null;
    retainAge = null;
  }



  /**
   * Creates a new generate server profile task with the provided information.
   *
   * @param  taskID           The task ID to use for this task.  If it is
   *                          {@code null} then a UUID will be generated for use
   *                          as the task ID.
   * @param  profileRoot      The path on the server filesystem to the zip file
   *                          or directory to which the generated server profile
   *                          will be written.  This may be an absolute path or
   *                          a relative path that will be interpreted as
   *                          relative to the instance root.  If the generated
   *                          server profile will be packaged into a zip file,
   *                          then this must either be the path to the zip file
   *                          to be created (which must not yet exist, although
   *                          its parent directory must exist) or the path to
   *                          the directory (which must already exists) in which
   *                          the zip file is to be created.  If the server
   *                          profile will not e zipped, then this must be the
   *                          path to an empty or nonexistent directory in a
   *                          parent directory that does exist.  If this is not
   *                          provided, the server will create the zip file or
   *                          profile directory in the instance root with a
   *                          name that it generates.
   * @param  includePaths     An optional list of paths to additional files or
   *                          directories that exist within the instance root
   *                          that should be included in the generated server
   *                          profile.  Relative paths will be interpreted as
   *                          relative to the instance root.  This may be
   *                          {@code null} or empty if no additional include
   *                          paths should be used.
   * @param  zipProfile       Indicates whether the generated server profile
   *                          should be packaged into a zip file.  If this is
   *                          {@code Boolean.TRUE}, then the profile will be
   *                          packaged into a zip file.  If this is
   *                          {@code Boolean.FALSE}, then the profile will be
   *                          written as a directory structure.  It may be
   *                          {@code null} if the server should choose whether
   *                          to package the profile into a zip file.
   * @param  retainCount      The minimum number of preexisting server profile
   *                          zip files to retain.  This may only be provided if
   *                          the profile is to be packaged into a zip file and
   *                          the profile root is specified as a directory so
   *                          that the server will generate the zip file name.
   *                          This may be {@code null} if only the retain age
   *                          will be used to identify which files may be
   *                          deleted (if a retain age is given), or if no
   *                          preexisting profile zip files should be removed
   *                          (if no retain age is given).
   * @param  retainAgeMillis  The minimum age in milliseconds of preexisting
   *                          server profile zip files to retain.  This may only
   *                          be provided if the profile is to be packaged into
   *                          a zip file and the profile root is specified as a
   *                          directory so that the server will generate the zip
   *                          file name.  This may be {@code null} if only the
   *                          retain count will be used to identify which files
   *                          may be deleted (if a retain count is given), or if
   *                          no preexisting profile zip files should be removed
   *                          (if no retain count is given).
   */
  public GenerateServerProfileTask(@Nullable final String taskID,
                                   @Nullable final String profileRoot,
                                   @Nullable final List<String> includePaths,
                                   @Nullable final Boolean zipProfile,
                                   @Nullable final Integer retainCount,
                                   @Nullable final Long retainAgeMillis)
  {
    this(taskID, profileRoot, includePaths, zipProfile, retainCount,
         retainAgeMillis, null, null, null, null, null, null, null, null, null,
         null);
  }



  /**
   * Creates a new generate server profile task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  profileRoot             The path on the server filesystem to the
   *                                 zip file or directory to which the
   *                                 generated server profile will be written.
   *                                 This may be an absolute path or a relative
   *                                 path that will be interpreted as relative
   *                                 to the instance root.  If the generated
   *                                 server profile will be packaged into a zip
   *                                 file, then this must either be the path to
   *                                 the zip file to be created (which must not
   *                                 yet exist, although its parent directory
   *                                 must exist) or the path to the directory
   *                                 (which must already exists) in which the
   *                                 zip file is to be created.  If the server
   *                                 profile will not e zipped, then this must
   *                                 be the path to an empty or nonexistent
   *                                 directory in a parent directory that does
   *                                 exist.  If this is not provided, the server
   *                                 will create the zip file or profile
   *                                 directory in the instance root with a name
   *                                 that it generates.
   * @param  includePaths            An optional list of paths to additional
   *                                 files or directories that exist within the
   *                                 instance root that should be included in
   *                                 the generated server profile.  Relative
   *                                 paths will be interpreted as relative to
   *                                 the instance root.  This may be
   *                                 {@code null} or empty if no additional
   *                                 include paths should be used.
   * @param  zipProfile              Indicates whether the generated server
   *                                 profile should be packaged into a zip file.
   *                                 If this is {@code Boolean.TRUE}, then the
   *                                 profile will be packaged into a zip file.
   *                                 If this is {@code Boolean.FALSE}, then the
   *                                 profile will be written as a directory
   *                                 structure.  It may be {@code null} if the
   *                                 server should choose whether to package the
   *                                 profile into a zip file.
   * @param  retainCount             The minimum number of preexisting server
   *                                 profile zip files to retain.  This may only
   *                                 be provided if the profile is to be
   *                                 packaged into a zip file and the profile
   *                                 root is specified as a directory so that
   *                                 the server will generate the zip file name.
   *                                 This may be {@code null} if only the retain
   *                                 age will be used to identify which files
   *                                 may be deleted (if a retain age is given),
   *                                 or if no preexisting profile zip files
   *                                 should be removed (if no retain age is
   *                                 given).
   * @param  retainAgeMillis         The minimum age in milliseconds of
   *                                 preexisting server profile zip files to
   *                                 retain.  This may only be provided if the
   *                                 profile is to be packaged into a zip file
   *                                 and the profile root is specified as a
   *                                 directory so that the server will generate
   *                                 the zip file name.  This may be
   *                                 {@code null} if only the retain count will
   *                                 be used to identify which files may be
   *                                 deleted (if a retain count is given), or if
   *                                 no preexisting profile zip files should be
   *                                 removed (if no retain count is given).
   * @param  scheduledStartTime      The time that this task should start
   *                                 running.
   * @param  dependencyIDs           The list of task IDs that will be required
   *                                 to complete before this task will be
   *                                 eligible to start.
   * @param  failedDependencyAction  Indicates what action should be taken if
   *                                 any of the dependencies for this task do
   *                                 not complete successfully.
   * @param  notifyOnStart           The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 starts running.
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnSuccess         The list of e-mail addresses of individuals
   *                                 that should be notified if this task
   *                                 completes successfully.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   * @param  alertOnStart            Indicates whether the server should send an
   *                                 alert notification when this task starts.
   * @param  alertOnSuccess          Indicates whether the server should send an
   *                                 alert notification if this task completes
   *                                 successfully.
   * @param  alertOnError            Indicates whether the server should send an
   *                                 alert notification if this task fails to
   *                                 complete successfully.
   */
  public GenerateServerProfileTask(@Nullable final String taskID,
              @Nullable final String profileRoot,
              @Nullable final List<String> includePaths,
              @Nullable final Boolean zipProfile,
              @Nullable final Integer retainCount,
              @Nullable final Long retainAgeMillis,
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
    super(taskID, GENERATE_SERVER_PROFILE_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    this.profileRoot = profileRoot;
    this.zipProfile = zipProfile;
    this.retainCount = retainCount;

    if (includePaths == null)
    {
      this.includePaths = Collections.emptyList();
    }
    else
    {
      this.includePaths =
           Collections.unmodifiableList(new ArrayList<>(includePaths));
    }

    if (retainAgeMillis == null)
    {
      retainAge = null;
    }
    else
    {
      retainAge = DurationArgument.nanosToDuration(
           TimeUnit.MILLISECONDS.toNanos(retainAgeMillis));
    }
  }



  /**
   * Creates a new generate server profile task from the provided entry.
   *
   * @param  entry  The entry to use to create this generate server profile
   *                task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a
   *                         generate server profile task entry.
   */
  public GenerateServerProfileTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);

    profileRoot = entry.getAttributeValue(ATTR_PROFILE_ROOT);
    zipProfile = entry.getAttributeValueAsBoolean(ATTR_ZIP);
    retainCount = entry.getAttributeValueAsInteger(ATTR_RETAIN_COUNT);

    final String[] includePathValues =
         entry.getAttributeValues(ATTR_INCLUDE_PATH);
    if (includePathValues == null)
    {
      includePaths = Collections.emptyList();
    }
    else
    {
      includePaths =
           Collections.unmodifiableList(Arrays.asList(includePathValues));
    }

    retainAge = entry.getAttributeValue(ATTR_RETAIN_AGE);
    if (retainAge != null)
    {
      try
      {
        DurationArgument.parseDuration(retainAge, TimeUnit.MILLISECONDS);
      }
      catch (final ArgumentException e)
      {
        Debug.debugException(e);
        throw new TaskException(
             ERR_GENERATE_SERVER_PROFILE_ENTRY_INVALID_RETAIN_AGE.get(
                  entry.getDN(), retainAge, e.getMessage()),
             e);
      }
    }
  }



  /**
   * Creates a generate server profile task from the provided set of task
   * properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid generate server profile task.
   */
  public GenerateServerProfileTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(GENERATE_SERVER_PROFILE_TASK_CLASS, properties);

    Boolean zip = null;
    Long rCount = null;
    String profRoot = null;
    String rAge = null;
    final List<String> incPaths = new ArrayList<>();
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = p.getAttributeName();
      final List<Object> values = entry.getValue();

      if (attrName.equalsIgnoreCase(ATTR_PROFILE_ROOT))
      {
        profRoot = parseString(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_INCLUDE_PATH))
      {
        final String[] pathArray = parseStrings(p, values, null);
        if (pathArray != null)
        {
          incPaths.addAll(Arrays.asList(pathArray));
        }
      }
      else if (attrName.equalsIgnoreCase(ATTR_ZIP))
      {
        zip = parseBoolean(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_RETAIN_COUNT))
      {
        rCount = parseLong(p, values, null);
      }
      else if (attrName.equalsIgnoreCase(ATTR_RETAIN_AGE))
      {
        rAge = parseString(p, values, null);
        try
        {
          DurationArgument.parseDuration(rAge, TimeUnit.MILLISECONDS);
        }
        catch (final ArgumentException e)
        {
          Debug.debugException(e);
          throw new TaskException(
               ERR_GENERATE_SERVER_PROFILE_PROPS_INVALID_RETAIN_AGE.get(
                    rAge, e.getMessage()));
        }
      }
    }

    profileRoot = profRoot;
    includePaths = incPaths;
    zipProfile = zip;
    retainAge = rAge;

    if (rCount == null)
    {
      retainCount = null;
    }
    else
    {
      retainCount = rCount.intValue();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_GENERATE_SERVER_PROFILE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_GENERATE_SERVER_PROFILE.get();
  }



  /**
   * Retrieves the path on the server filesystem to the zip file or directory to
   * which the generated server profile will be written.  It may be an absolute
   * path or a relative path that will be interpreted as relative to the
   * instance root.
   *
   * @return  The path on the server filesystem to the zip file or directory to
   *          which the generated server profile will be written, or
   *          {@code null} if the server will create the zip file or profile
   *          directory in the instance root with a generated name.
   */
  @Nullable()
  public String getProfileRoot()
  {
    return profileRoot;
  }



  /**
   * Retrieves a list of additional paths to files or directories within the
   * instance root that should be included in the generated server profile.
   *
   * @return  A list of additional paths to files or directories within the
   *          instance root that should be included in the generated server
   *          profile, or an empty list if no additional paths should be
   *          included.
   */
  @NotNull()
  public List<String> getIncludePaths()
  {
    return includePaths;
  }



  /**
   * Retrieves a flag that indicates whether the server should package the
   * generated server profile into a zip file.
   *
   * @return  {@code Boolean.TRUE} if the generated server profile should be
   *          packaged into a zip file, {@code Boolean.FALSE} if the server
   *          profile should be written as a directory structure, or
   *          {@code null} if this is not specified and the server will decide
   *          which behavior to exhibit.
   */
  @Nullable()
  public Boolean getZipProfile()
  {
    return zipProfile;
  }



  /**
   * Retrieves the maximum number of preexisting server profile zip files to
   * retain after a new profile is successfully generated, if defined.
   *
   * @return  The maximum number of preexisting server profile zip files to
   *          retain after a new profile is successfully generated, or
   *          {@code null} if file retention processing should depend only on
   *          the retain age (if defined) or if no retention processing should
   *          be performed.
   */
  @Nullable()
  public Integer getRetainCount()
  {
    return retainCount;
  }



  /**
   * Retrieves the maximum age of preexisting server profile zip files to
   * retain after a new profile is successfully generated, if defined.  The
   * value will be formatted as a duration as used by the
   * {@link DurationArgument} class, which is an integer followed by a time
   * unit (millisecond, second, minute, hour, day, or week, or one of their
   * plurals).
   *
   * @return  The maximum age of preexisting server profile zip files to
   *          retain after a new profile is successfully generated, or
   *          {@code null} if file retention processing should depend only on
   *          the retain count (if defined) or if no retention processing should
   *          be performed.
   */
  @Nullable()
  public String getRetainAge()
  {
    return retainAge;
  }



  /**
   * Retrieves the maximum age in milliseconds of preexisting server profile zip
   * files to retain after a new profile is successfully generated, if defined.
   *
   * @return  The maximum age in milliseconds of preexisting server profile zip
   *          files to retain after a new profile is successfully generated, or
   *          {@code null} if file retention processing should depend only on
   *          the retain count (if defined) or if no retention processing should
   *          be performed.
   *
   * @throws  TaskException  If a problem is encountered while attempting to
   *                         parse the retain age as a duration.
   */
  @Nullable()
  public Long getRetainAgeMillis()
         throws TaskException
  {
    if (retainAge == null)
    {
      return null;
    }

    try
    {
      return DurationArgument.parseDuration(retainAge, TimeUnit.MILLISECONDS);
    }
    catch (final ArgumentException e)
    {
      Debug.debugException(e);
      throw new TaskException(
           ERR_GENERATE_SERVER_PROFILE_CANNOT_PARSE_RETAIN_AGE.get(retainAge,
                e.getMessage()),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(
         OC_GENERATE_SERVER_PROFILE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final List<Attribute> attrList = new ArrayList<>(5);

    if (profileRoot != null)
    {
      attrList.add(new Attribute(ATTR_PROFILE_ROOT, profileRoot));
    }

    if (! includePaths.isEmpty())
    {
      attrList.add(new Attribute(ATTR_INCLUDE_PATH, includePaths));
    }

    if (zipProfile != null)
    {
      attrList.add(new Attribute(ATTR_ZIP, zipProfile.toString()));
    }

    if (retainCount != null)
    {
      attrList.add(new Attribute(ATTR_RETAIN_COUNT,
           String.valueOf(retainCount)));
    }

    if (retainAge != null)
    {
      attrList.add(new Attribute(ATTR_RETAIN_AGE, retainAge));
    }

    return Collections.unmodifiableList(attrList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(
         PROPERTY_PROFILE_ROOT,
         PROPERTY_INCLUDE_PATH,
         PROPERTY_ZIP,
         PROPERTY_RETAIN_COUNT,
         PROPERTY_RETAIN_AGE));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    if (profileRoot != null)
    {
      props.put(PROPERTY_PROFILE_ROOT,
           Collections.<Object>singletonList(profileRoot));
    }

    if (! includePaths.isEmpty())
    {
      props.put(PROPERTY_INCLUDE_PATH,
           Collections.<Object>unmodifiableList(includePaths));
    }

    if (zipProfile != null)
    {
      props.put(PROPERTY_ZIP,
           Collections.<Object>singletonList(zipProfile));
    }

    if (retainCount != null)
    {
      props.put(PROPERTY_RETAIN_COUNT,
           Collections.<Object>singletonList(retainCount.longValue()));
    }

    if (retainAge != null)
    {
      props.put(PROPERTY_RETAIN_AGE,
           Collections.<Object>singletonList(retainAge));
    }

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
