/*
 * Copyright 2018-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2019 Ping Identity Corporation
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
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to request that
 * the server should dynamically reload all key and trust manager providers
 * associated with all HTTP connection handlers configured with support for
 * HTTPS.  Note that this may cause problems with a client's ability to resume a
 * TLS session that was created before the reload.
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
 * The reload HTTP connection handler certificates task does not have any
 * task-specific properties.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReloadHTTPConnectionHandlerCertificatesTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class in the server that is used for
   * the reload HTTP connection handler certificates task.
   */
  static final String RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES_TASK_CLASS =
       "com.unboundid.directory.server.tasks." +
            "ReloadHTTPConnectionHandlerCertificatesTask";



  /**
   * The name of the object class used in reload HTTP connection handler
   * certificates task entries.
   */
  private static final String
       OC_RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES_TASK =
            "ds-task-reload-http-connection-handler-certificates";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 842594962305532389L;



  /**
   * Creates a new uninitialized reload HTTP connection handler certificates
   * task instance that should only be used for obtaining general information
   * about this task, including the task name, description, and supported
   * properties.
   */
  public ReloadHTTPConnectionHandlerCertificatesTask()
  {
    this(null, null, null, null, null, null);
  }



  /**
   * Creates a new reload HTTP connection handler certificates task with the
   * provided information.
   *
   * @param  taskID         The task ID to use for this task.  If it is
   *                        {@code null} then a UUID will be generated for use
   *                        as the task ID.
   */
  public ReloadHTTPConnectionHandlerCertificatesTask(final String taskID)
  {
    this(taskID, null, null, null, null, null);
  }



  /**
   * Creates a new reload HTTP connection handler certificates task with the
   * provided information.
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
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   */
  public ReloadHTTPConnectionHandlerCertificatesTask(final String taskID,
              final Date scheduledStartTime, final List<String> dependencyIDs,
              final FailedDependencyAction failedDependencyAction,
              final List<String> notifyOnCompletion,
              final List<String> notifyOnError)
  {
    this(taskID, scheduledStartTime, dependencyIDs, failedDependencyAction,
         null, notifyOnCompletion, null, notifyOnError, null, null, null);
  }



  /**
   * Creates a new reload HTTP connection handler certificates task with the
   * provided information.
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
  public ReloadHTTPConnectionHandlerCertificatesTask(final String taskID,
              final Date scheduledStartTime, final List<String> dependencyIDs,
              final FailedDependencyAction failedDependencyAction,
              final List<String> notifyOnStart,
              final List<String> notifyOnCompletion,
              final List<String> notifyOnSuccess,
              final List<String> notifyOnError, final Boolean alertOnStart,
              final Boolean alertOnSuccess, final Boolean alertOnError)
  {
    super(taskID, RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES_TASK_CLASS,
         scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnStart, notifyOnCompletion, notifyOnSuccess, notifyOnError,
         alertOnStart, alertOnSuccess, alertOnError);
  }



  /**
   * Creates a new reload HTTP connection handler certificates task from the
   * provided entry.
   *
   * @param  entry  The entry to use to create this reload HTTP connection
   *                handler certificates task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a reload
   *                         HTTP connection handler certificates task entry.
   */
  public ReloadHTTPConnectionHandlerCertificatesTask(final Entry entry)
         throws TaskException
  {
    super(entry);
  }



  /**
   * Creates a new reload HTTP connection handler certificates task from the
   * provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid reload HTTP connection handler
   *                         certificates task.
   */
  public ReloadHTTPConnectionHandlerCertificatesTask(
              final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES_TASK_CLASS, properties);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES.
         get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(
         OC_RELOAD_HTTP_CONNECTION_HANDLER_CERTIFICATES_TASK);
  }
}
