/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a thread that will be registered as a JVM shutdown hook
 * for any command-line tool for which invocation logging is to be performed.
 * If the tool is interrupted by a JVM shutdown (for example, if the JVM
 * receives a kill signal, if the user presses Control+C, or the tool calls
 * System.exit) before it can complete naturally, then this shutdown hook thread
 * will be run to try to ensure that the tool invocation log includes a record
 * of the abnormal shutdown.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ToolInvocationLogShutdownHook
       extends Thread
{
  // An object with information about the logging that should be performed.
  private final ToolInvocationLogDetails logDetails;



  /**
   * Creates a new instance of this shutdown hook with the provided log details.
   *
   * @param  logDetails  The log details of the tool.  It must not be
   *                     {@code null}.
   */
  public ToolInvocationLogShutdownHook(
              final ToolInvocationLogDetails logDetails)
  {
    this.logDetails = logDetails;
  }



  /**
   * Logs a completion message indicating that tool processing was interrupted
   * by a JVM shutdown.
   */
  @Override()
  public void run()
  {
    ToolInvocationLogger.logCompletionMessage(logDetails, null,
         INFO_TOOL_INTERRUPTED_BY_JVM_SHUTDOWN.get());
  }
}
