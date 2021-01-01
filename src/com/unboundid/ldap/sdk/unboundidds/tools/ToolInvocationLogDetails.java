/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.PrintStream;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class represents a data structure that contains information that should
 * be used when logging launch and completion messages for a tool invocation.
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
public final class ToolInvocationLogDetails
{
  // Indicates whether to log launch and completion messages for the associated
  // tool.
  private final boolean logInvocation;

  // A print stream that may be used to report information about any problems
  // encountered while attempting to perform invocation logging.
  @NotNull private final PrintStream toolErrorStream;

  // The set of log files in which invocation logging should be performed.
  @NotNull private final Set<File> logFiles;

  // The name of the command used to invoke the tool.
  @NotNull private final String commandName;

  // An identifier that will appear in launch and completion messages for the
  // tool so that those messages can be correlated for the same invocation of
  // the tool.
  @NotNull private final String invocationID;



  /**
   * Creates a new tool invocation log details object with the provided
   * information.
   *
   * @param  logInvocation    Indicates whether to perform launch and completion
   *                          logging for the associated tool.
   * @param  commandName      The name (without any path information) for the
   *                          provided tool.  It must not be {@code null}.
   * @param  invocationID     A unique identifier that will be used to correlate
   *                          launch and completion messages for the same
   *                          invocation of the tool.  If this is {@code null},
   *                          then an identifier will be generated.
   * @param  logFiles         The set of log files in which launch and
   *                          completion messages should be recorded.  It may be
   *                          {@code null} or empty if no invocation logging
   *                          should be performed for this tool.  It must not be
   *                          {@code null} or empty if invocation logging should
   *                          be performed.
   * @param  toolErrorStream  A print stream that may be used to report
   *                          information about any problems encountered while
   *                          attempting to perform invocation logging.  It
   *                          must not be {@code null}.
   */
  private ToolInvocationLogDetails(final boolean logInvocation,
                                   @NotNull final String commandName,
                                   @Nullable final String invocationID,
                                   @Nullable final Set<File> logFiles,
                                   @NotNull final PrintStream toolErrorStream)
  {
    this.logInvocation = logInvocation;
    this.commandName = commandName;
    this.toolErrorStream = toolErrorStream;

    if (invocationID == null)
    {
      this.invocationID = UUID.randomUUID().toString();
    }
    else
    {
      this.invocationID = invocationID;
    }

    if (logFiles == null)
    {
      this.logFiles = Collections.emptySet();
    }
    else
    {
      this.logFiles = Collections.unmodifiableSet(logFiles);
    }
  }



  /**
   * Creates a new {@code ToolInvocationLogDetails} instance that indicates that
   * no logging should be performed for the specified tool.
   *
   * @param  commandName  The name of the command (without any path information)
   *                      for the associated tool.  It must not be {@code null}.
   *
   * @return  The {@code ToolInvocationLogDetails} object that was created.
   */
  @NotNull()
  static ToolInvocationLogDetails createDoNotLogDetails(
                                       @NotNull final String commandName)
  {
    return new ToolInvocationLogDetails(false, commandName, "",
         Collections.<File>emptySet(), NullOutputStream.getPrintStream());
  }



  /**
   * Creates a new {@code ToolInvocationLogDetails} instance that indicates that
   * launch and completion messages should be logged for the specified tool.
   *
   * @param  commandName      The name (without any path information) for the
   *                          provided tool.  It must not be {@code null}.
   * @param  invocationID     A unique identifier that will be used to correlate
   *                          launch and completion messages for the same
   *                          invocation of the tool.  If this is {@code null},
   *                          then an identifier will be generated.
   * @param  logFiles         The set of log files in which launch and
   *                          completion messages should be recorded.  It may be
   *                          {@code null} or empty if no invocation logging
   *                          should be performed for this tool.  It must not be
   *                          {@code null} or empty if invocation logging should
   *                          be performed.
   * @param  toolErrorStream  A print stream that should be used to report
   *                          information about any problems encountered while
   *                          attempting to perform invocation logging.  It
   *                          must not be {@code null}.
   *
   * @return  The {@code ToolInvocationLogDetails} object that was created.
   */
  @NotNull()
  static ToolInvocationLogDetails createLogDetails(
              @NotNull final String commandName,
              @Nullable final String invocationID,
              @NotNull final Set<File> logFiles,
              @NotNull final PrintStream toolErrorStream)
  {
    return new ToolInvocationLogDetails(true, commandName, invocationID,
         logFiles, toolErrorStream);
  }



  /**
   * Retrieves the name of the command (without any path information) for the
   * associated tool.
   *
   * @return  The name of the command for the associated tool.
   */
  @NotNull()
  public String getCommandName()
  {
    return commandName;
  }



  /**
   * Indicates whether launch and completion messages should be logged for the
   * tool.
   *
   * @return  {@code true} if the messages should be logged, or {@code false} if
   *          not.
   */
  public boolean logInvocation()
  {
    return logInvocation;
  }



  /**
   * Retrieves the unique identifier to use to correlate the launch and
   * completion messages for the tool invocation, if available.
   *
   * @return  The unique identifier to use to correlate the launch and
   *          completion messages for the tool invocation, or an empty string if
   *          no invocation logging should be performed for the tool.
   */
  @NotNull()
  public String getInvocationID()
  {
    return invocationID;
  }



  /**
   * Retrieves an unmodifiable set of the files in which launch and completion
   * log messages should be recorded for the tool invocation.
   *
   * @return  An unmodifiable set of the files in which launch and completion
   *          log messages should be recorded for the tool invocation.  It may
   *          be empty if no invocation logging should be performed.
   */
  @NotNull()
  public Set<File> getLogFiles()
  {
    return logFiles;
  }



  /**
   * Retrieves a print stream that may be used to report information about any
   * problems encountered while attempting to perform invocation logging.
   *
   * @return  A print stream that may be used to report information about any
   *          problems encountered while attempting to perform invocation
   *          logging.
   */
  @NotNull()
  public PrintStream getToolErrorStream()
  {
    return toolErrorStream;
  }


  /**
   * Retrieves a string representation of this tool invocation log details
   * object.
   *
   * @return  A string representation of this tool invocation log details
   *          object.
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
   * Appends a string representation of this tool invocation log details
   * object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ToolInvocationLogDetails(commandName='");
    buffer.append(commandName);
    buffer.append("', logInvocation=");
    buffer.append(logInvocation);

    if (logInvocation)
    {
      buffer.append(", invocationID='");
      buffer.append(invocationID);
      buffer.append("', logFiles={");

      final Iterator<File> fileIterator = logFiles.iterator();
      while (fileIterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(fileIterator.next().getAbsolutePath());
        buffer.append('\'');

        if (fileIterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
