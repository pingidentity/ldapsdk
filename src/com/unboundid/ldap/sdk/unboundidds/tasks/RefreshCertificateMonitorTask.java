/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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



import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to request that
 * the server refresh the certificate monitor data immediately.  It does not
 * have any custom configuration properties.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RefreshCertificateMonitorTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the refresh
   * certificate monitor task in the Directory Server.
   */
  @NotNull static final String REFRESH_CERTIFICATE_MONITOR_TASK_CLASS =
       "com.unboundid.directory.server.tasks.RefreshCertificateMonitorTask";



  /**
   * The name of the object class used in refresh certificate monitor task
   * entries.
   */
  @NotNull private static final String OC_REFRESH_CERTIFICATE_MONITOR_TASK =
       "ds-task-refresh-certificate-monitor";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7576460767480962435L;



  /**
   * Creates a new refresh certificate monitor task with a randomly generated
   * task ID and default values for all other settings.
   */
  public RefreshCertificateMonitorTask()
  {
    this((String) null);
  }



  /**
   * Creates a new refresh certificate monitor task with the provided
   * task ID and default values for all other settings.
   *
   * @param  taskID  The task ID to use for this task.  If it is {@code null}
   *                 then a UUID will be generated for use as the task ID.
   */
  public RefreshCertificateMonitorTask(@Nullable final String taskID)
  {
    this(taskID, null, null, null, null, null, null, null, null, null, null);
  }



  /**
   * Creates a new refresh certificate monitor task with the provided
   * information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
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
  public RefreshCertificateMonitorTask(
              @Nullable final String taskID,
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
    super(taskID, REFRESH_CERTIFICATE_MONITOR_TASK_CLASS, scheduledStartTime,
         dependencyIDs, failedDependencyAction, notifyOnStart,
         notifyOnCompletion, notifyOnSuccess, notifyOnError, alertOnStart,
         alertOnSuccess, alertOnError);
  }



  /**
   * Creates a new refresh certificate monitor task from the provided entry.
   *
   * @param  entry  The entry to use to create this refresh certificate monitor
   *                task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a refresh
   *                         certificate monitor task entry.
   */
  public RefreshCertificateMonitorTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);
  }



  /**
   * Creates a new refresh certificate monitor task from the provided set of
   * task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid refresh certificate monitor task.
   */
  public RefreshCertificateMonitorTask(
              @NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(REFRESH_CERTIFICATE_MONITOR_TASK_CLASS, properties);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_REFRESH_CERTIFICATE_MONITOR.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_REFRESH_CERTIFICATE_MONITOR.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_REFRESH_CERTIFICATE_MONITOR_TASK);
  }
}
