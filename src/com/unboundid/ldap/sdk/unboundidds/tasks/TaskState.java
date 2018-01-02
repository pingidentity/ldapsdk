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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines a task state, which provides information about the current
 * state of processing for a scheduled task.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TaskState
{
  /**
   * The task state that indicates that the task was canceled before it started
   * running.
   */
  CANCELED_BEFORE_STARTING("canceled_before_starting"),



  /**
   * The task state that indicates that the task has completed successfully.
   */
  COMPLETED_SUCCESSFULLY("completed_successfully"),



  /**
   * The task state that indicates that the task has completed but with one or
   * more errors.
   */
  COMPLETED_WITH_ERRORS("completed_with_errors"),



  /**
   * The task state that indicates that the task has been disabled.
   */
  DISABLED("disabled"),



  /**
   * The task state that indicates that the task is running.
   */
  RUNNING("running"),



  /**
   * The task state that indicates that the task was forced to stop running when
   * it was canceled by an administrator.
   */
  STOPPED_BY_ADMINISTRATOR("stopped_by_administrator"),



  /**
   * The task state that indicates that the task was forced to stop running when
   * it encountered an unrecoverable error.
   */
  STOPPED_BY_ERROR("stopped_by_error"),



  /**
   * The task state that indicates that the task was forced to stop running when
   * the task scheduler was shut down.
   */
  STOPPED_BY_SHUTDOWN("stopped_by_shutdown"),



  /**
   * The task state that indicates that the task has not yet been scheduled.
   */
  UNSCHEDULED("unscheduled"),



  /**
   * The task state that indicates that the task has one or more unsatisfied
   * dependencies.
   */
  WAITING_ON_DEPENDENCY("waiting_on_dependency"),



  /**
   * The task state that indicates that the task is waiting on the start time to
   * arrive.
   */
  WAITING_ON_START_TIME("waiting_on_start_time");



  // The name of this failed dependency action.
  private final String name;



  /**
   * Creates a new task state with the specified name.
   *
   * @param  name  The name of the task state to create.
   */
  TaskState(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name of this task state.
   *
   * @return  The name of this task state.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the task state with the specified name.
   *
   * @param  name  The name of the task state to retrieve.
   *
   * @return  The requested task state, or {@code null} if there is no state
   *          with the given name.
   */
  public static TaskState forName(final String name)
  {
    final String lowerName = toLowerCase(name);

    if (lowerName.equals("canceled_before_starting"))
    {
      return CANCELED_BEFORE_STARTING;
    }
    else if (lowerName.equals("completed_successfully"))
    {
      return COMPLETED_SUCCESSFULLY;
    }
    else if (lowerName.equals("completed_with_errors"))
    {
      return COMPLETED_WITH_ERRORS;
    }
    else if (lowerName.equals("disabled"))
    {
      return DISABLED;
    }
    else if (lowerName.equals("running"))
    {
      return RUNNING;
    }
    else if (lowerName.equals("stopped_by_administrator"))
    {
      return STOPPED_BY_ADMINISTRATOR;
    }
    else if (lowerName.equals("stopped_by_error"))
    {
      return STOPPED_BY_ERROR;
    }
    else if (lowerName.equals("stopped_by_shutdown"))
    {
      return STOPPED_BY_SHUTDOWN;
    }
    else if (lowerName.equals("unscheduled"))
    {
      return UNSCHEDULED;
    }
    else if (lowerName.equals("waiting_on_dependency"))
    {
      return WAITING_ON_DEPENDENCY;
    }
    else if (lowerName.equals("waiting_on_start_time"))
    {
      return WAITING_ON_START_TIME;
    }
    else
    {
      return null;
    }
  }



  /**
   * Indicates whether this task state indicates that the task has not yet
   * started running.
   *
   * @return  {@code true} if this task state indicates that the task has not
   *          yet started, or {@code false} if not.
   */
  public boolean isPending()
  {
    switch (this)
    {
      case DISABLED:
      case UNSCHEDULED:
      case WAITING_ON_DEPENDENCY:
      case WAITING_ON_START_TIME:
        return true;
      default:
        return false;
    }
  }



  /**
   * Indicates whether this task state indicates that the task is currently
   * running.
   *
   * @return  {@code true} if this task state indicates that the task is
   *          currently running, or {@code false} if not.
   */
  public boolean isRunning()
  {
    return (this == RUNNING);
  }



  /**
   * Indicates whether this task state indicates that the task has completed all
   * of the processing that it will do.
   *
   * @return  {@code true} if this task state indicates that the task has
   *          completed all of the processing that it will do, or {@code false}
   *          if not.
   */
  public boolean isCompleted()
  {
    return (! (isPending() || isRunning()));
  }



  /**
   * Retrieves a string representation of this task state.
   *
   * @return  A string representation of this task state.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
