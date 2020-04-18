/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020 Ping Identity Corporation
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
 * Copyright (C) 2015-2020 Ping Identity Corporation
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
 *     The path to the zip file (if the profile is to be packaged into a zip
 *     file) or directory (if it is not to be packaged into a zip file) to which
 *     the server profile will be written.  This may be an absolute path or a
 *     relative path that will be interpreted as relative to the instance root.
 *     If this is omitted, then a zip file or directory will be created within
 *     the instance root directory with a generated name.
 *   </LI>
 *   <LI>
 *     An optional set of additional paths to files or directories within the
 *     instance root that should be included in the server profile.  If this is
 *     omitted, then no additional include paths will be used.
 *   </LI>
 *   <LI>
 *     A flag indicating whether the generated server profile should be packaged
 *     into a zip file.  If this is omitted, then the server will determine
 *     whether to package the profile into a zip file.
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
  static final String GENERATE_SERVER_PROFILE_TASK_CLASS =
       "com.unboundid.directory.server.tasks.GenerateServerProfileTask";



  /**
   * The name of the attribute used to specify additional paths within the
   * instance root that should be included in the generated server profile.
   */
  private static final String ATTR_INCLUDE_PATH =
       "ds-task-generate-server-profile-include-path";



  /**
   * The name of the attribute used to specify the path to which the generated
   * profile should be written.
   */
  private static final String ATTR_PROFILE_ROOT =
       "ds-task-generate-server-profile-root";



  /**
   * The name of the attribute used to indicate whether the generated server
   * profile should be packaged into a zip file.
   */
  private static final String ATTR_ZIP =
       "ds-task-generate-server-profile-zip";



  /**
   * The name of the object class used in generate server profile task entries.
   */
  private static final String OC_GENERATE_SERVER_PROFILE_TASK =
       "ds-task-generate-server-profile";



  /**
   * The task property that will be used for the optional include paths.
   */
  private static final TaskProperty PROPERTY_INCLUDE_PATH = new TaskProperty(
       ATTR_INCLUDE_PATH,
       INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_INCLUDE_PATH.get(),
       INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_INCLUDE_PATH.get(),
       String.class, false, true, false);



  /**
   * The task property that will be used for the profile root.
   */
  private static final TaskProperty PROPERTY_PROFILE_ROOT = new TaskProperty(
       ATTR_PROFILE_ROOT,
       INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_PROFILE_ROOT.get(),
       INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_PROFILE_ROOT.get(),
       String.class, false, false, false);



  /**
   * The task property that will be used to indicate whether to package the
   * server profile in a zip file.
   */
  private static final TaskProperty PROPERTY_ZIP = new TaskProperty(ATTR_ZIP,
       INFO_GENERATE_SERVER_PROFILE_ATTR_DISPLAY_NAME_ZIP.get(),
       INFO_GENERATE_SERVER_PROFILE_ATTR_DESCRIPTION_ZIP.get(),
       Boolean.class, false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1263255691625581165L;



  // Indicates whether to package the generated server profile into a zip file.
  private final Boolean zipProfile;

  // The list of additional paths within the instance root that should be
  // included in the generated server profile.
  private final List<String> includePaths;

  // The path to the zip file or directory to which the generated server profile
  // will be written.
  private final String profileRoot;



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
  }



  /**
   * Creates a new generate server profile task with the provided information.
   *
   * @param  taskID        The task ID to use for this task.  If it is
   *                       {@code null} then a UUID will be generated for use as
   *                       the task ID.
   * @param  profileRoot   The path on the server filesystem to the zip file or
   *                       directory to which the generated server profile will
   *                       be written.  This may be an absolute path or a
   *                       relative path that will be interpreted as relative to
   *                       the instance root.  If the generated server profile
   *                       will be packaged into a zip file, then this must be
   *                       the path to a file that does not yet exist in a
   *                       parent directory that does exist.  If the server
   *                       profile will not be zipped, then this must be the
   *                       path to an empty or nonexistent directory in a parent
   *                       directory that does exist.  If this is not provided,
   *                       the server will create the zip file or profile
   *                       directory in the instance root with a generated name.
   * @param  includePaths  An optional list of paths to additional files or
   *                       directories that exist within the instance root that
   *                       should be included in the generated server profile.
   *                       Relative paths will be interpreted as relative to the
   *                       instance root.  This may be {@code null} or empty if
   *                       no additional include paths should be used.
   * @param  zipProfile    Indicates whether the generated server profile should
   *                       be packaged into a zip file.  If this is
   *                       {@code Boolean.TRUE}, then the profile will be
   *                       packaged into a zip file.  If this is
   *                       {@code Boolean.FALSE}, then the profile will be
   *                       written as a directory structure.  It may be
   *                       {@code null} if the server should choose whether to
   *                       package the profile into a zip file.
   */
  public GenerateServerProfileTask(final String taskID,
                                   final String profileRoot,
                                   final List<String> includePaths,
                                   final Boolean zipProfile)
  {
    this(taskID, profileRoot, includePaths, zipProfile, null, null, null, null,
         null, null, null, null, null, null);
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
   *                                 file, then this must be the path to a file
   *                                 that does not yet exist in a parent
   *                                 directory that does exist.  If the server
   *                                 profile will not be zipped, then this must
   *                                 be the path to an empty or nonexistent
   *                                 directory in a parent directory that does
   *                                 exist.  If this is not provided, the
   *                                 server will create the zip file or profile
   *                                 directory in the instance root with a
   *                                 generated name.
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
  public GenerateServerProfileTask(final String taskID,
                           final String profileRoot,
                           final List<String> includePaths,
                           final Boolean zipProfile,
                           final Date scheduledStartTime,
                           final List<String> dependencyIDs,
                           final FailedDependencyAction failedDependencyAction,
                           final List<String> notifyOnStart,
                           final List<String> notifyOnCompletion,
                           final List<String> notifyOnSuccess,
                           final List<String> notifyOnError,
                           final Boolean alertOnStart,
                           final Boolean alertOnSuccess,
                           final Boolean alertOnError)
  {
    super(taskID, GENERATE_SERVER_PROFILE_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);

    this.profileRoot = profileRoot;
    this.zipProfile = zipProfile;

    if (includePaths == null)
    {
      this.includePaths = Collections.emptyList();
    }
    else
    {
      this.includePaths =
           Collections.unmodifiableList(new ArrayList<>(includePaths));
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
  public GenerateServerProfileTask(final Entry entry)
         throws TaskException
  {
    super(entry);

    profileRoot = entry.getAttributeValue(ATTR_PROFILE_ROOT);
    zipProfile = entry.getAttributeValueAsBoolean(ATTR_ZIP);

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
              final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(GENERATE_SERVER_PROFILE_TASK_CLASS, properties);

    Boolean zip = null;
    String profRoot = null;
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
    }

    profileRoot = profRoot;
    includePaths = incPaths;
    zipProfile = zip;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_GENERATE_SERVER_PROFILE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
  public Boolean getZipProfile()
  {
    return zipProfile;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(
         OC_GENERATE_SERVER_PROFILE_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    final List<Attribute> attrList = new ArrayList<>(3);

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

    return Collections.unmodifiableList(attrList);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    return Collections.unmodifiableList(Arrays.asList(
         PROPERTY_PROFILE_ROOT,
         PROPERTY_INCLUDE_PATH,
         PROPERTY_ZIP));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
