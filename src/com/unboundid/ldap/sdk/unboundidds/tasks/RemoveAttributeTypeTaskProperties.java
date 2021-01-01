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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a set of properties that may be used when creating a
 * {@link RemoveAttributeTypeTask}.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class RemoveAttributeTypeTaskProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8648887754165247809L;



  // Indicates whether to generate an administrative alert if the task completes
  // with an error.
  @Nullable private Boolean alertOnError;

  // Indicates whether to generate an administrative alert when the task starts
  // running.
  @Nullable private Boolean alertOnStart;

  // Indicates whether to generate an administrative alert if the task completes
  // successfully.
  @Nullable private Boolean alertOnSuccess;

  // The time at which the task should start running.
  @Nullable private Date scheduledStartTime;

  // The action to take if any of the dependencies for this task complete
  // unsuccessfully.
  @Nullable private FailedDependencyAction failedDependencyAction;

  // The dependency IDs of any tasks on which the remove attribute type task
  // should depend.
  @NotNull private final List<String> dependencyIDs;

  // The addresses to email whenever the task completes, regardless of success
  // or failure.
  @NotNull private final List<String> notifyOnCompletion;

  // The addresses to email if the task completes with an error.
  @NotNull private final List<String> notifyOnError;

  // The addresses to email when the task starts.
  @NotNull private final List<String> notifyOnStart;

  // The addresses to email if the task completes successfully.
  @NotNull private final List<String> notifyOnSuccess;

  // The name of the attribute to be removed from the schema.
  @NotNull private String attributeType;

  // The task ID to use for the remove attribute type task.
  @Nullable private String taskID;



  /**
   * Creates a new set of remove attribute type task properties.  It will use
   * default values for all general task properties.
   *
   * @param  attributeType  The name or OID of the attribute type to remove from
   *                        the server schema.
   */
  public RemoveAttributeTypeTaskProperties(@NotNull final String attributeType)
  {
    this.attributeType = attributeType;

    alertOnError = null;
    alertOnStart = null;
    alertOnSuccess = null;
    scheduledStartTime = null;
    failedDependencyAction = null;
    dependencyIDs = new ArrayList<>(5);
    notifyOnCompletion = new ArrayList<>(5);
    notifyOnError = new ArrayList<>(5);
    notifyOnStart = new ArrayList<>(5);
    notifyOnSuccess = new ArrayList<>(5);
    taskID = null;
  }



  /**
   * Creates a new set of remove attribute type task properties as a copy of the
   * provided properties.
   *
   * @param  properties  The remove attribute type task properties to duplicate.
   */
  public RemoveAttributeTypeTaskProperties(
              @NotNull final RemoveAttributeTypeTaskProperties properties)
  {
    attributeType = properties.getAttributeType();
    alertOnError = properties.getAlertOnError();
    alertOnStart = properties.getAlertOnStart();
    alertOnSuccess = properties.getAlertOnSuccess();
    scheduledStartTime = properties.getScheduledStartTime();
    failedDependencyAction = properties.getFailedDependencyAction();
    dependencyIDs = new ArrayList<>(properties.getDependencyIDs());
    notifyOnCompletion = new ArrayList<>(properties.getNotifyOnCompletion());
    notifyOnError = new ArrayList<>(properties.getNotifyOnError());
    notifyOnStart = new ArrayList<>(properties.getNotifyOnStart());
    notifyOnSuccess = new ArrayList<>(properties.getNotifyOnSuccess());
    taskID = properties.getTaskID();
  }



  /**
   * Creates a new set of remove attribute type task properties set from the
   * provided task instance.
   *
   * @param  task  The remove attribute type task instance from which the
   *               properties should be set.
   */
  public RemoveAttributeTypeTaskProperties(
              @NotNull final RemoveAttributeTypeTask task)
  {
    attributeType = task.getAttributeType();
    alertOnError = task.getAlertOnError();
    alertOnStart = task.getAlertOnStart();
    alertOnSuccess = task.getAlertOnSuccess();
    scheduledStartTime = task.getScheduledStartTime();
    failedDependencyAction = task.getFailedDependencyAction();
    dependencyIDs = new ArrayList<>(task.getDependencyIDs());
    notifyOnCompletion = new ArrayList<>(task.getNotifyOnCompletionAddresses());
    notifyOnError = new ArrayList<>(task.getNotifyOnErrorAddresses());
    notifyOnStart = new ArrayList<>(task.getNotifyOnStartAddresses());
    notifyOnSuccess = new ArrayList<>(task.getNotifyOnSuccessAddresses());
    taskID = task.getTaskID();
  }



  /**
   * Retrieves the name or OID of the attribute type to remove from the server
   * schema.
   *
   * @return  The name or OID of the attribute type to remove from the server
   *          schema.
   */
  @NotNull()
  public String getAttributeType()
  {
    return attributeType;
  }



  /**
   * Specifies the name or OID of the attribute type to remove from the server
   * schema.
   *
   * @param  attributeType  The name or OID of the attribute type to remove from
   *                        the server schema.
   */
  public void setAttributeType(@NotNull final String attributeType)
  {
    this.attributeType = attributeType;
  }



  /**
   * Retrieves the task ID that should be used for the task.
   *
   * @return  The task ID that should be used for the task, or {@code null} if a
   *          random UUID should be generated for use as the task ID.
   */
  @Nullable()
  public String getTaskID()
  {
    return taskID;
  }



  /**
   *Specifies the task ID that should be used for the task.
   *
   * @param  taskID  The task ID that should be used for the task.  It may be
   *                 {@code null} if a random UUID should be generated for use
   *                 as the task ID.
   */
  public void setTaskID(@Nullable final String taskID)
  {
    this.taskID = taskID;
  }



  /**
   * Retrieves the earliest time that the task should be eligible to start
   * running.
   *
   * @return  The earliest time that the task should be eligible to start
   *          running, or {@code null} if the task should be eligible to start
   *          immediately (or as soon as all of its dependencies have been
   *          satisfied).
   */
  @Nullable()
  public Date getScheduledStartTime()
  {
    return scheduledStartTime;
  }



  /**
   * Specifies the earliest time that the task should be eligible to start
   * running.
   *
   * @param  scheduledStartTime  The earliest time that the task should be
   *                             eligible to start running.  It may be
   *                             {@code null} if the task should be eligible to
   *                             start immediately (or as soon as all of its
   *                             dependencies have been satisfied).
   */
  public void setScheduledStartTime(@Nullable final Date scheduledStartTime)
  {
    this.scheduledStartTime = scheduledStartTime;
  }



  /**
   * Retrieves the task IDs for any tasks that must complete before the new
   * remove attribute type task will be eligible to start running.
   *
   * @return  The task IDs for any tasks that must complete before the new
   *          remove attribute type task will be eligible to start running, or
   *          an empty list if the new task should not depend on any other
   *          tasks.
   */
  @NotNull()
  public List<String> getDependencyIDs()
  {
    return new ArrayList<>(dependencyIDs);
  }



  /**
   * Specifies the task IDs for any tasks that must complete before the new
   * remove attribute type task will be eligible to start running.
   *
   * @param  dependencyIDs  The task IDs for any tasks that must complete before
   *                        the new remove attribute type task will be eligible
   *                        to start running.  It may be {@code null} or empty
   *                        if the new task should not depend on any other
   *                        tasks.
   */
  public void setDependencyIDs(@Nullable final List<String> dependencyIDs)
  {
    this.dependencyIDs.clear();
    if (dependencyIDs != null)
    {
      this.dependencyIDs.addAll(dependencyIDs);
    }
  }



  /**
   * Retrieves the action that the server should take if any of the tasks on
   * which the new task depends did not complete successfully.
   *
   * @return  The action that the server should take if any of the tasks on
   *          which the new task depends did not complete successfully, or
   *          {@code null} if the property should not be specified when creating
   *          the task (and the server should choose an appropriate failed
   *          dependency action).
   */
  @Nullable()
  public FailedDependencyAction getFailedDependencyAction()
  {
    return failedDependencyAction;
  }



  /**
   * Specifies the action that the server should take if any of the tasks on
   * which the new task depends did not complete successfully.
   *
   * @param  failedDependencyAction  The action that the server should take if
   *                                 any of the tasks on which the new task
   *                                 depends did not complete successfully.  It
   *                                 may be {@code null} if the property should
   *                                 not be specified when creating the task
   *                                 (and the server should choose an
   *                                 appropriate failed dependency action).
   */
  public void setFailedDependencyAction(
       @Nullable final FailedDependencyAction failedDependencyAction)
  {
    this.failedDependencyAction = failedDependencyAction;
  }



  /**
   * Retrieves the addresses to email whenever the task starts running.
   *
   * @return  The addresses to email whenever the task starts running, or an
   *          empty list if no email notification should be sent when starting
   *          the task.
   */
  @NotNull()
  public List<String> getNotifyOnStart()
  {
    return new ArrayList<>(notifyOnStart);
  }



  /**
   * Specifies the addresses to email whenever the task starts running.
   *
   * @param  notifyOnStart  The addresses to email whenever the task starts
   *                        running.  It amy be {@code null} or empty if no
   *                        email notification should be sent when starting the
   *                        task.
   */
  public void setNotifyOnStart(@Nullable final List<String> notifyOnStart)
  {
    this.notifyOnStart.clear();
    if (notifyOnStart != null)
    {
      this.notifyOnStart.addAll(notifyOnStart);
    }
  }



  /**
   * Retrieves the addresses to email whenever the task completes, regardless of
   * its success or failure.
   *
   * @return  The addresses to email whenever the task completes, or an
   *          empty list if no email notification should be sent when the task
   *          completes.
   */
  @NotNull()
  public List<String> getNotifyOnCompletion()
  {
    return new ArrayList<>(notifyOnCompletion);
  }



  /**
   * Specifies the addresses to email whenever the task completes, regardless of
   * its success or failure.
   *
   * @param  notifyOnCompletion  The addresses to email whenever the task
   *                             completes.  It amy be {@code null} or empty if
   *                             no email notification should be sent when the
   *                             task completes.
   */
  public void setNotifyOnCompletion(
                   @Nullable final List<String> notifyOnCompletion)
  {
    this.notifyOnCompletion.clear();
    if (notifyOnCompletion != null)
    {
      this.notifyOnCompletion.addAll(notifyOnCompletion);
    }
  }



  /**
   * Retrieves the addresses to email if the task completes successfully.
   *
   * @return  The addresses to email if the task completes successfully, or an
   *          empty list if no email notification should be sent on successful
   *          completion.
   */
  @NotNull()
  public List<String> getNotifyOnSuccess()
  {
    return new ArrayList<>(notifyOnSuccess);
  }



  /**
   * Specifies the addresses to email if the task completes successfully.
   *
   * @param  notifyOnSuccess  The addresses to email if the task completes
   *                          successfully.  It amy be {@code null} or empty if
   *                          no email notification should be sent on
   *                          successful completion.
   */
  public void setNotifyOnSuccess(@Nullable final List<String> notifyOnSuccess)
  {
    this.notifyOnSuccess.clear();
    if (notifyOnSuccess != null)
    {
      this.notifyOnSuccess.addAll(notifyOnSuccess);
    }
  }



  /**
   * Retrieves the addresses to email if the task does not complete
   * successfully.
   *
   * @return  The addresses to email if the task does not complete successfully,
   *          or an empty list if no email notification should be sent on an
   *          unsuccessful completion.
   */
  @NotNull()
  public List<String> getNotifyOnError()
  {
    return new ArrayList<>(notifyOnError);
  }



  /**
   * Specifies the addresses to email if the task does not complete
   * successfully.
   *
   * @param  notifyOnError  The addresses to email if the task does not complete
   *                        successfully.  It amy be {@code null} or empty if
   *                        no email notification should be sent on an
   *                        unsuccessful completion.
   */
  public void setNotifyOnError(@Nullable final List<String> notifyOnError)
  {
    this.notifyOnError.clear();
    if (notifyOnError != null)
    {
      this.notifyOnError.addAll(notifyOnError);
    }
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification when the task starts running.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification when the task starts running,
   *          or {@code null} if the property should not be specified when the
   *          task is created (and the server will default to not sending any
   *          alert).
   */
  @Nullable()
  public Boolean getAlertOnStart()
  {
    return alertOnStart;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification when the task starts running.
   *
   * @param  alertOnStart  The flag that indicates whether the server should
   *                       send an administrative alert notification when the
   *                       task starts running,  It may be {@code null} if the
   *                       property should not be specified when the task is
   *                       created (and the server will default to not sending
   *                       any alert).
   */
  public void setAlertOnStart(@Nullable final Boolean alertOnStart)
  {
    this.alertOnStart = alertOnStart;
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification if the task completes successfully.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification if the task completes
   *          successfully, or {@code null} if the property should not be
   *          specified when the task is created (and the server will default to
   *          not sending any alert).
   */
  @Nullable()
  public Boolean getAlertOnSuccess()
  {
    return alertOnSuccess;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification if the task completes successfully.
   *
   * @param  alertOnSuccess  The flag that indicates whether the server should
   *                         send an administrative alert notification if the
   *                         task completes successfully,  It may be
   *                         {@code null} if the property should not be
   *                         specified when the task is created (and the server
   *                         will default to not sending any alert).
   */
  public void setAlertOnSuccess(@Nullable final Boolean alertOnSuccess)
  {
    this.alertOnSuccess = alertOnSuccess;
  }



  /**
   * Retrieves the flag that indicates whether the server should send an
   * administrative alert notification if the task does not complete
   * successfully.
   *
   * @return  The flag that indicates whether the server should send an
   *          administrative alert notification if the task does not complete
   *          successfully, or {@code null} if the property should not be
   *          specified when the task is created (and the server will default to
   *          not sending any alert).
   */
  @Nullable()
  public Boolean getAlertOnError()
  {
    return alertOnError;
  }



  /**
   * Specifies the flag that indicates whether the server should send an
   * administrative alert notification if the task does not complete
   * successfully.
   *
   * @param  alertOnError  The flag that indicates whether the server should
   *                       send an administrative alert notification if the task
   *                       does not complete successfully,  It may be
   *                       {@code null} if the property should not be specified
   *                       when the task is created (and the server will default
   *                       to not sending any alert).
   */
  public void setAlertOnError(@Nullable final Boolean alertOnError)
  {
    this.alertOnError = alertOnError;
  }



  /**
   * Retrieves a string representation of this remove attribute type task
   * properties object.
   *
   * @return  A string representation of this remove attribute type task
   *          properties object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this remove attribute type task
   * properties object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation will be
   *                 appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RemoveAttributeTypeProperties(");

    appendNameValuePair(buffer, "taskID", taskID);
    appendNameValuePair(buffer, "attributeType", attributeType);
    appendNameValuePair(buffer, "scheduledStartTime", scheduledStartTime);
    appendNameValuePair(buffer, "dependencyIDs", dependencyIDs);
    appendNameValuePair(buffer, "failedDependencyAction",
         failedDependencyAction);
    appendNameValuePair(buffer, "notifyOnStart", notifyOnStart);
    appendNameValuePair(buffer, "notifyOnCompletion", notifyOnCompletion);
    appendNameValuePair(buffer, "notifyOnSuccess", notifyOnSuccess);
    appendNameValuePair(buffer, "notifyOnError", notifyOnError);
    appendNameValuePair(buffer, "alertOnStart", alertOnStart);
    appendNameValuePair(buffer, "alertOnSuccess", alertOnSuccess);
    appendNameValuePair(buffer, "alertOnError", alertOnError);

    buffer.append(')');
  }



  /**
   * Appends a name-value pair to the provided buffer, if the value is
   * non-{@code null}.
   *
   * @param  buffer  The buffer to which the name-value pair should be appended.
   * @param  name    The name to be used.  It must not be {@code null}.
   * @param  value   The value to be used.  It may be {@code null} if there is
   *                 no value for the property.
   */
  private static void appendNameValuePair(@NotNull final StringBuilder buffer,
                                          @NotNull final String name,
                                          @Nullable final Object value)
  {
    if (value == null)
    {
      return;
    }

    if ((buffer.length() > 0) &&
         (buffer.charAt(buffer.length() - 1) != '('))
    {
      buffer.append(", ");
    }

    buffer.append(name);
    buffer.append("='");
    buffer.append(value);
    buffer.append('\'');
  }



  /**
   * Appends a name-value pair to the provided buffer, if the value is
   * non-{@code null}.
   *
   * @param  buffer   The buffer to which the name-value pair should be
   *                  appended.
   * @param  name     The name to be used.  It must not be {@code null}.
   * @param  values   The list of values to be used.  It may be {@code null} or
   *                  empty if there are no values for the property.
   */
  private static void appendNameValuePair(@NotNull final StringBuilder buffer,
                                          @NotNull final String name,
                                          @Nullable final List<String> values)
  {
    if ((values == null) || values.isEmpty())
    {
      return;
    }

    if ((buffer.length() > 0) &&
         (buffer.charAt(buffer.length() - 1) != '('))
    {
      buffer.append(", ");
    }

    buffer.append(name);
    buffer.append("={ ");

    final Iterator<String> iterator = values.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append('}');
  }
}
