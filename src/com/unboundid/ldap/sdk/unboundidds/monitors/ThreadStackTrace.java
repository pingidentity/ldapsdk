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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a data structure that can hold information about a thread
 * stack trace read from the Directory Server's stack trace monitor.
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
 * The information available in a thread stack trace includes:
 * <UL>
 *   <LI>The name of the thread.  This is generally a user-friendly string that
 *       indicates what that thread does within the server.</LI>
 *   <LI>The thread ID that is assigned to the thread by the JVM.</LI>
 *   <LI>The stack trace frames for that thread as a list of
 *       {@link StackTraceElement} objects.</LI>
 * </UL>
 * See the documentation in the {@link StackTraceMonitorEntry} class for
 * information about accessing the Directory Server stack trace.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ThreadStackTrace
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5032934844534051999L;



  // The thread ID for this thread.
  private final int threadID;

  // The list of stack trace elements for the thread.
  @NotNull private final List<StackTraceElement> stackTraceElements;

  // The name for this thread.
  @NotNull private final String threadName;



  /**
   * Creates a new thread stack trace with the provided information.
   *
   * @param  threadID            The thread ID for the associated thread.
   * @param  threadName          The name for the associated thread.
   * @param  stackTraceElements  A list of the stack trace elements for the
   *                             associated thread.  It may be empty if no stack
   *                             trace was available.
   */
  public ThreadStackTrace(final int threadID, @NotNull final String threadName,
              @NotNull final List<StackTraceElement> stackTraceElements)
  {
    this.threadID           = threadID;
    this.threadName         = threadName;
    this.stackTraceElements = Collections.unmodifiableList(stackTraceElements);
  }



  /**
   * Retrieves the thread ID for the associated thread.
   *
   * @return  The thread ID for the associated thread.
   */
  public int getThreadID()
  {
    return threadID;
  }



  /**
   * Retrieves the name of the associated thread.
   *
   * @return  The name of the associated thread.
   */
  @NotNull()
  public String getThreadName()
  {
    return threadName;
  }



  /**
   * Retrieves the list of stack trace elements for the associated thread.
   *
   * @return  The list of stack trace elements for the associated thread, or an
   *          empty list if no stack trace was available.
   */
  @NotNull()
  public List<StackTraceElement> getStackTraceElements()
  {
    return stackTraceElements;
  }
}
