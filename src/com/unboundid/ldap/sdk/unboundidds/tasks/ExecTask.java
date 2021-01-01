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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;



/**
 * This class defines a Directory Server task that can be used to cause the
 * server to execute a specified command with a given set of arguments.
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
 * The server imposes limitation on the commands that can be executed and on the
 * circumstances in which they can be invoked.  See the
 * exec-command-whitelist.txt file in the server's config directory for a
 * summary of these restrictions, and for additional information about exec
 * tasks.
 * <BR><BR>
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>The absolute path to the command to execute.  This must be
 *       provided.</LI>
 *   <LI>An optional string with arguments to provide to the command.</LI>
 *   <LI>An optional path to a file to which the command's output should be
 *       written.</LI>
 *   <LI>An optional boolean flag that indicates whether to log the command's
 *       output to the server error log.</LI>
 *   <LI>An optional string that specifies the task state that should be used
 *       if the command completes with a nonzero exit code.</LI>
 *   <LI>An optional string that specifies the path to the working directory to
 *       use when executing the command.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExecTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the exec task.
   */
  @NotNull static final String EXEC_TASK_CLASS =
       "com.unboundid.directory.server.tasks.ExecTask";



  /**
   * The name of the attribute used to specify the absolute path for the command
   * to be executed.
   */
  @NotNull private static final String ATTR_COMMAND_PATH =
       "ds-task-exec-command-path";



  /**
   * The name of the attribute used to specify the argument string to provide
   * when running the command.
   */
  @NotNull private static final String ATTR_COMMAND_ARGUMENTS =
       "ds-task-exec-command-arguments";



  /**
   * The name of the attribute used to specify the path to a file in which the
   * command's output should be recorded.
   */
  @NotNull private static final String ATTR_COMMAND_OUTPUT_FILE =
       "ds-task-exec-command-output-file";



  /**
   * The name of the attribute used to indicate whether to record the command's
   * output in the server error log.
   */
  @NotNull private static final String ATTR_LOG_COMMAND_OUTPUT =
       "ds-task-exec-log-command-output";



  /**
   * The name of the attribute used to specify the task state for commands that
   * complete with a nonzero exit code.
   */
  @NotNull private static final String ATTR_TASK_STATE_FOR_NONZERO_EXIT_CODE =
       "ds-task-exec-task-completion-state-for-nonzero-exit-code";



  /**
   * The name of the attribute used to specify the path to the working directory
   * to use when executing the command.
   */
  @NotNull private static final String ATTR_WORKING_DIRECTORY =
       "ds-task-exec-working-directory";



  /**
   * The name of the object class used in EXEC task entries.
   */
  @NotNull private static final String OC_EXEC_TASK = "ds-task-exec";



  /**
   * The task property that will be used for the command path.
   */
  @NotNull private static final TaskProperty PROPERTY_COMMAND_PATH =
     new TaskProperty(ATTR_COMMAND_PATH,
          INFO_EXEC_DISPLAY_NAME_COMMAND_PATH.get(),
          INFO_EXEC_DESCRIPTION_COMMAND_PATH.get(), String.class, true, false,
          false);



  /**
   * The task property that will be used for the command arguments.
   */
  @NotNull private static final TaskProperty PROPERTY_COMMAND_ARGUMENTS =
     new TaskProperty(ATTR_COMMAND_ARGUMENTS,
          INFO_EXEC_DISPLAY_NAME_COMMAND_ARGUMENTS.get(),
          INFO_EXEC_DESCRIPTION_COMMAND_ARGUMENTS.get(), String.class, false,
          false, false);



  /**
   * The task property that will be used for the command output file.
   */
  @NotNull private static final TaskProperty PROPERTY_COMMAND_OUTPUT_FILE =
     new TaskProperty(ATTR_COMMAND_OUTPUT_FILE,
          INFO_EXEC_DISPLAY_NAME_COMMAND_OUTPUT_FILE.get(),
          INFO_EXEC_DESCRIPTION_COMMAND_OUTPUT_FILE.get(), String.class, false,
          false, false);



  /**
   * The task property that will be used for the log command output flag.
   */
  @NotNull private static final TaskProperty PROPERTY_LOG_COMMAND_OUTPUT =
     new TaskProperty(ATTR_LOG_COMMAND_OUTPUT,
          INFO_EXEC_DISPLAY_NAME_LOG_COMMAND_OUTPUT.get(),
          INFO_EXEC_DESCRIPTION_LOG_COMMAND_OUTPUT.get(), Boolean.class, false,
          false, false);



  /**
   * The task property that will be used for the task state for commands that
   * complete with a nonzero exit code.
   */
  @NotNull private static final TaskProperty
       PROPERTY_TASK_STATE_FOR_NONZERO_EXIT_CODE = new TaskProperty(
            ATTR_TASK_STATE_FOR_NONZERO_EXIT_CODE,
            INFO_EXEC_DISPLAY_NAME_TASK_STATE_FOR_NONZERO_EXIT_CODE.get(),
            INFO_EXEC_DESCRIPTION_TASK_STATE_FOR_NONZERO_EXIT_CODE.get(),
            String.class, false, false, false,
            new String[]
            {
              "STOPPED_BY_ERROR",
              "STOPPED-BY-ERROR",
              "COMPLETED_WITH_ERRORS",
              "COMPLETED-WITH-ERRORS",
              "COMPLETED_SUCCESSFULLY",
              "COMPLETED-SUCCESSFULLY"
            });



  /**
   * The task property that will be used for path to use as the the path to the
   * working directory to use when executing the command.
   */
  @NotNull private static final TaskProperty PROPERTY_WORKING_DIRECTORY =
     new TaskProperty(ATTR_WORKING_DIRECTORY,
          INFO_EXEC_DISPLAY_NAME_WORKING_DIRECTORY.get(),
          INFO_EXEC_DESCRIPTION_WORKING_DIRECTORY.get(),
          String.class, false, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1647609631634328008L;



  // Indicates whether command output is to be logged.
  @Nullable private final Boolean logCommandOutput;

  // The arguments to provide when executing the command.
  @Nullable private final String commandArguments;

  // The path to the file to which command output should be written.
  @Nullable private final String commandOutputFile;

  // The path to the command to be executed.
  @NotNull private final String commandPath;

  // The name of the task state that should be used if the command completes
  // with a nonzero exit code.
  @Nullable private final String taskStateForNonZeroExitCode;

  // The path to the working directory to use when executing the command.
  @Nullable private final String workingDirectory;



  /**
   * Creates a new, uninitialized exec task instance that should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public ExecTask()
  {
    commandPath = null;
    commandArguments = null;
    commandOutputFile = null;
    logCommandOutput = null;
    taskStateForNonZeroExitCode = null;
    workingDirectory = null;
  }



  /**
   * Creates a new exec task with the provided information.
   *
   * @param  commandPath
   *              The absolute path (on the server filesystem) to the command
   *              that should be executed.  This must not be {@code null}.
   * @param  commandArguments
   *              The complete set of arguments that should be used when
   *              running the command.  This may be {@code null} if no arguments
   *              should be provided.
   * @param  commandOutputFile
   *              The path to an output file that should be used to record all
   *              output that the command writes to standard output or standard
   *              error.  This may be {@code null} if the command output should
   *              not be recorded in a file.
   * @param  logCommandOutput
   *              Indicates whether to record the command output in the server
   *              error log.  If this is {@code true}, then all non-blank lines
   *              that the command writes to standard output or standard error
   *              will be recorded in the server error log.  if this is
   *              {@code false}, then the output will not be recorded in the
   *              server error log.  If this is {@code null}, then the server
   *              will determine whether to log command output.  Note that a
   *              value of {@code true} should only be used if you are certain
   *              that the tool will only generate text-based output, and you
   *              should use {@code false} if you know that the command may
   *              generate non-text output.
   * @param  taskStateForNonZeroExitCode
   *              The task state that should be used if the command completes
   *              with a nonzero exit code.  This may be {@code null} to
   *              indicate that the server should determine the appropriate task
   *              state.  If it is non-{@code null}, then the value must be one
   *              of {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public ExecTask(@NotNull final String commandPath,
                  @Nullable final String commandArguments,
                  @Nullable final String commandOutputFile,
                  @Nullable final Boolean logCommandOutput,
                  @Nullable final TaskState taskStateForNonZeroExitCode)
         throws TaskException
  {
    this(null, commandPath, commandArguments, commandOutputFile,
         logCommandOutput, taskStateForNonZeroExitCode, null, null, null, null,
         null);
  }



  /**
   * Creates a new exec task with the provided information.
   *
   * @param  commandPath
   *              The absolute path (on the server filesystem) to the command
   *              that should be executed.  This must not be {@code null}.
   * @param  commandArguments
   *              The complete set of arguments that should be used when
   *              running the command.  This may be {@code null} if no arguments
   *              should be provided.
   * @param  commandOutputFile
   *              The path to an output file that should be used to record all
   *              output that the command writes to standard output or standard
   *              error.  This may be {@code null} if the command output should
   *              not be recorded in a file.
   * @param  logCommandOutput
   *              Indicates whether to record the command output in the server
   *              error log.  If this is {@code true}, then all non-blank lines
   *              that the command writes to standard output or standard error
   *              will be recorded in the server error log.  if this is
   *              {@code false}, then the output will not be recorded in the
   *              server error log.  If this is {@code null}, then the server
   *              will determine whether to log command output.  Note that a
   *              value of {@code true} should only be used if you are certain
   *              that the tool will only generate text-based output, and you
   *              should use {@code false} if you know that the command may
   *              generate non-text output.
   * @param  taskStateForNonZeroExitCode
   *              The task state that should be used if the command completes
   *              with a nonzero exit code.  This may be {@code null} to
   *              indicate that the server should determine the appropriate task
   *              state.  If it is non-{@code null}, then the value must be one
   *              of {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   * @param  workingDirectory
   *              The path to the working directory to use when executing the
   *              command.
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public ExecTask(@NotNull final String commandPath,
                  @Nullable final String commandArguments,
                  @Nullable final String commandOutputFile,
                  @Nullable final Boolean logCommandOutput,
                  @Nullable final TaskState taskStateForNonZeroExitCode,
                  @Nullable final String workingDirectory)
         throws TaskException
  {
    this(null, commandPath, commandArguments, commandOutputFile,
         logCommandOutput, taskStateForNonZeroExitCode, workingDirectory, null,
         null, null, null, null, null, null, null, null, null);
  }



  /**
   * Creates a new exec task with the provided information.
   *
   * @param  taskID
   *              The task ID to use for this task.  If it is {@code null} then
   *              a UUID will be generated for use as the task ID.
   * @param  commandPath
   *              The absolute path (on the server filesystem) to the command
   *              that should be executed.  This must not be {@code null}.
   * @param  commandArguments
   *              The complete set of arguments that should be used when
   *              running the command.  This may be {@code null} if no arguments
   *              should be provided.
   * @param  commandOutputFile
   *              The path to an output file that should be used to record all
   *              output that the command writes to standard output or standard
   *              error.  This may be {@code null} if the command output should
   *              not be recorded in a file.
   * @param  logCommandOutput
   *              Indicates whether to record the command output in the server
   *              error log.  If this is {@code true}, then all non-blank lines
   *              that the command writes to standard output or standard error
   *              will be recorded in the server error log.  if this is
   *              {@code false}, then the output will not be recorded in the
   *              server error log.  If this is {@code null}, then the server
   *              will determine whether to log command output.  Note that a
   *              value of {@code true} should only be used if you are certain
   *              that the tool will only generate text-based output, and you
   *              should use {@code false} if you know that the command may
   *              generate non-text output.
   * @param  taskStateForNonZeroExitCode
   *              The task state that should be used if the command completes
   *              with a nonzero exit code.  This may be {@code null} to
   *              indicate that the server should determine the appropriate task
   *              state.  If it is non-{@code null}, then the value must be one
   *              of {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   * @param  scheduledStartTime
   *              The time that this task should start running.
   * @param  dependencyIDs
   *              The list of task IDs that will be required to complete before
   *              this task will be eligible to start.
   * @param  failedDependencyAction
   *              Indicates what action should be taken if any of the
   *              dependencies for this task do not complete successfully.
   * @param  notifyOnCompletion
   *              The list of e-mail addresses of individuals that should be
   *              notified when this task completes.
   * @param  notifyOnError
   *              The list of e-mail addresses of individuals that should be
   *              notified if this task does not complete successfully.
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public ExecTask(@Nullable final String taskID,
                  @NotNull final String commandPath,
                  @Nullable final String commandArguments,
                  @Nullable final String commandOutputFile,
                  @Nullable final Boolean logCommandOutput,
                  @Nullable final TaskState taskStateForNonZeroExitCode,
                  @Nullable final Date scheduledStartTime,
                  @Nullable final List<String> dependencyIDs,
                  @Nullable final FailedDependencyAction failedDependencyAction,
                  @Nullable final List<String> notifyOnCompletion,
                  @Nullable final List<String> notifyOnError)
         throws TaskException
  {
    this(taskID, commandPath, commandArguments, commandOutputFile,
         logCommandOutput, taskStateForNonZeroExitCode, scheduledStartTime,
         dependencyIDs, failedDependencyAction, null, notifyOnCompletion,
         null, notifyOnError, null, null, null);
  }



  /**
   * Creates a new exec task with the provided information.
   *
   * @param  taskID
   *              The task ID to use for this task.  If it is {@code null} then
   *              a UUID will be generated for use as the task ID.
   * @param  commandPath
   *              The absolute path (on the server filesystem) to the command
   *              that should be executed.  This must not be {@code null}.
   * @param  commandArguments
   *              The complete set of arguments that should be used when
   *              running the command.  This may be {@code null} if no arguments
   *              should be provided.
   * @param  commandOutputFile
   *              The path to an output file that should be used to record all
   *              output that the command writes to standard output or standard
   *              error.  This may be {@code null} if the command output should
   *              not be recorded in a file.
   * @param  logCommandOutput
   *              Indicates whether to record the command output in the server
   *              error log.  If this is {@code true}, then all non-blank lines
   *              that the command writes to standard output or standard error
   *              will be recorded in the server error log.  if this is
   *              {@code false}, then the output will not be recorded in the
   *              server error log.  If this is {@code null}, then the server
   *              will determine whether to log command output.  Note that a
   *              value of {@code true} should only be used if you are certain
   *              that the tool will only generate text-based output, and you
   *              should use {@code false} if you know that the command may
   *              generate non-text output.
   * @param  taskStateForNonZeroExitCode
   *              The task state that should be used if the command completes
   *              with a nonzero exit code.  This may be {@code null} to
   *              indicate that the server should determine the appropriate task
   *              state.  If it is non-{@code null}, then the value must be one
   *              of {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
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
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public ExecTask(@Nullable final String taskID,
                  @NotNull final String commandPath,
                  @Nullable final String commandArguments,
                  @Nullable final String commandOutputFile,
                  @Nullable final Boolean logCommandOutput,
                  @Nullable final TaskState taskStateForNonZeroExitCode,
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
         throws TaskException
  {
    this(taskID, commandPath, commandArguments, commandOutputFile,
         logCommandOutput, taskStateForNonZeroExitCode, null,
         scheduledStartTime, dependencyIDs, failedDependencyAction,
         notifyOnStart, notifyOnCompletion, notifyOnSuccess, notifyOnError,
         alertOnStart, alertOnSuccess, alertOnError);
  }



  /**
   * Creates a new exec task with the provided information.
   *
   * @param  taskID
   *              The task ID to use for this task.  If it is {@code null} then
   *              a UUID will be generated for use as the task ID.
   * @param  commandPath
   *              The absolute path (on the server filesystem) to the command
   *              that should be executed.  This must not be {@code null}.
   * @param  commandArguments
   *              The complete set of arguments that should be used when
   *              running the command.  This may be {@code null} if no arguments
   *              should be provided.
   * @param  commandOutputFile
   *              The path to an output file that should be used to record all
   *              output that the command writes to standard output or standard
   *              error.  This may be {@code null} if the command output should
   *              not be recorded in a file.
   * @param  logCommandOutput
   *              Indicates whether to record the command output in the server
   *              error log.  If this is {@code true}, then all non-blank lines
   *              that the command writes to standard output or standard error
   *              will be recorded in the server error log.  if this is
   *              {@code false}, then the output will not be recorded in the
   *              server error log.  If this is {@code null}, then the server
   *              will determine whether to log command output.  Note that a
   *              value of {@code true} should only be used if you are certain
   *              that the tool will only generate text-based output, and you
   *              should use {@code false} if you know that the command may
   *              generate non-text output.
   * @param  taskStateForNonZeroExitCode
   *              The task state that should be used if the command completes
   *              with a nonzero exit code.  This may be {@code null} to
   *              indicate that the server should determine the appropriate task
   *              state.  If it is non-{@code null}, then the value must be one
   *              of {@link TaskState#STOPPED_BY_ERROR},
   *              {@link TaskState#COMPLETED_WITH_ERRORS}, or
   *              {@link TaskState#COMPLETED_SUCCESSFULLY}.
   * @param  workingDirectory
   *              The path to the working directory to use when executing the
   *              command.
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
   *
   * @throws  TaskException  If there is a problem with any of the provided
   *                         arguments.
   */
  public ExecTask(@Nullable final String taskID,
                  @NotNull final String commandPath,
                  @Nullable final String commandArguments,
                  @Nullable final String commandOutputFile,
                  @Nullable final Boolean logCommandOutput,
                  @Nullable final TaskState taskStateForNonZeroExitCode,
                  @Nullable final String workingDirectory,
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
         throws TaskException
  {
    super(taskID, EXEC_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnStart, notifyOnCompletion,
         notifyOnSuccess, notifyOnError, alertOnStart, alertOnSuccess,
         alertOnError);

    this.commandPath = commandPath;
    this.commandArguments = commandArguments;
    this.commandOutputFile = commandOutputFile;
    this.logCommandOutput = logCommandOutput;
    this.workingDirectory = workingDirectory;

    if ((commandPath == null) || commandPath.isEmpty())
    {
      throw new TaskException(ERR_EXEC_MISSING_PATH.get());
    }

    if (taskStateForNonZeroExitCode == null)
    {
      this.taskStateForNonZeroExitCode = null;
    }
    else
    {
      switch (taskStateForNonZeroExitCode)
      {
        case STOPPED_BY_ERROR:
        case COMPLETED_WITH_ERRORS:
        case COMPLETED_SUCCESSFULLY:
          this.taskStateForNonZeroExitCode = taskStateForNonZeroExitCode.name();
          break;
        default:
          throw new TaskException(
               ERR_EXEC_INVALID_STATE_FOR_NONZERO_EXIT_CODE.get(
                    TaskState.STOPPED_BY_ERROR.name(),
                    TaskState.COMPLETED_WITH_ERRORS.name(),
                    TaskState.COMPLETED_SUCCESSFULLY.name()));
      }
    }
  }



  /**
   * Creates a new exec task from the provided entry.
   *
   * @param  entry  The entry to use to create this exec task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as an exec
   *                         task entry.
   */
  public ExecTask(@NotNull final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the command to execute.  It must be provided.
    commandPath = entry.getAttributeValue(ATTR_COMMAND_PATH);
    if (commandPath == null)
    {
      throw new TaskException(ERR_EXEC_ENTRY_MISSING_COMMAND_PATH.get(
           entry.getDN(), ATTR_COMMAND_PATH));
    }

    commandArguments = entry.getAttributeValue(ATTR_COMMAND_ARGUMENTS);
    commandOutputFile = entry.getAttributeValue(ATTR_COMMAND_OUTPUT_FILE);
    logCommandOutput =
         entry.getAttributeValueAsBoolean(ATTR_LOG_COMMAND_OUTPUT);
    taskStateForNonZeroExitCode =
         entry.getAttributeValue(ATTR_TASK_STATE_FOR_NONZERO_EXIT_CODE);
    workingDirectory = entry.getAttributeValue(ATTR_WORKING_DIRECTORY);
  }



  /**
   * Creates a new exec task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid exec task.
   */
  public ExecTask(@NotNull final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(EXEC_TASK_CLASS, properties);

    String path = null;
    String arguments = null;
    String outputFile = null;
    Boolean logOutput = null;
    String nonZeroExitState = null;
    String workingDir = null;
    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = StaticUtils.toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();

      if (attrName.equals(ATTR_COMMAND_PATH))
      {
        path = parseString(p, values, path);
      }
      else if (attrName.equals(ATTR_COMMAND_ARGUMENTS))
      {
        arguments = parseString(p, values, arguments);
      }
      else if (attrName.equals(ATTR_COMMAND_OUTPUT_FILE))
      {
        outputFile = parseString(p, values, outputFile);
      }
      else if (attrName.equals(ATTR_LOG_COMMAND_OUTPUT))
      {
        logOutput = parseBoolean(p, values, logOutput);
      }
      else if (attrName.equals(ATTR_TASK_STATE_FOR_NONZERO_EXIT_CODE))
      {
        nonZeroExitState = parseString(p, values, nonZeroExitState);
      }
      else if (attrName.equals(ATTR_WORKING_DIRECTORY))
      {
        workingDir = parseString(p, values, workingDir);
      }
    }

    commandPath = path;
    commandArguments = arguments;
    commandOutputFile = outputFile;
    logCommandOutput = logOutput;
    taskStateForNonZeroExitCode = nonZeroExitState;
    workingDirectory = workingDir;

    if (commandPath == null)
    {
      throw new TaskException(ERR_EXEC_PROPERTIES_MISSING_COMMAND_PATH.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskName()
  {
    return INFO_TASK_NAME_EXEC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_EXEC.get();
  }



  /**
   * Retrieves the path to the command to be executed.
   *
   * @return  The path to the command to be executed.
   */
  @NotNull()
  public String getCommandPath()
  {
    return commandPath;
  }



  /**
   * Retrieves a string with the values of the arguments that should be provided
   * when running the command.
   *
   * @return  A string with the values of the arguments that should be provided
   *          when running the command, or {@code null} if the command should be
   *          run without any arguments.
   */
  @Nullable()
  public String getCommandArguments()
  {
    return commandArguments;
  }



  /**
   * Retrieves the path to a file to which the command's output should be
   * written.
   *
   * @return  The path to a file to which the command's output should be
   *          written, or {@code null} if the output should not be written to a
   *          file.
   */
  @Nullable()
  public String getCommandOutputFile()
  {
    return commandOutputFile;
  }



  /**
   * Indicates whether the command's output should be recorded in the server's
   * error log.
   *
   * @return  {@code true} if the command's output should be recorded in the
   *          server's error log, {@code false} if the output should not be
   *          logged, or {@code null} if the task should not specify the
   *          behavior.
   */
  @Nullable()
  public Boolean logCommandOutput()
  {
    return logCommandOutput;
  }



  /**
   * Retrieves a string representation of the task state that should be returned
   * if the command completes with a nonzero exit code.
   *
   * @return  A string representation of the task state that should be returned
   *          if the command completes with a nonzero exit state, or
   *          {@code null} if the task should not specify the return state.
   */
  @Nullable()
  public String getTaskStateForNonZeroExitCode()
  {
    return taskStateForNonZeroExitCode;
  }



  /**
   * Retrieves the path to the working directory to use when executing the
   * command.
   *
   * @return  The path to the working directory to use when executing the
   *          command, or {@code null} if the task should not specify the
   *          working directory and the server root directory should be used by
   *          default.
   */
  @Nullable()
  public String getWorkingDirectory()
  {
    return workingDirectory;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<String> getAdditionalObjectClasses()
  {
    return Collections.singletonList(OC_EXEC_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Attribute> getAdditionalAttributes()
  {
    final LinkedList<Attribute> attrList = new LinkedList<>();
    attrList.add(new Attribute(ATTR_COMMAND_PATH, commandPath));

    if (commandArguments != null)
    {
      attrList.add(new Attribute(ATTR_COMMAND_ARGUMENTS, commandArguments));
    }

    if (commandOutputFile != null)
    {
      attrList.add(new Attribute(ATTR_COMMAND_OUTPUT_FILE, commandOutputFile));
    }

    if (logCommandOutput != null)
    {
      attrList.add(new Attribute(ATTR_LOG_COMMAND_OUTPUT,
           String.valueOf(logCommandOutput)));
    }

    if (taskStateForNonZeroExitCode != null)
    {
      attrList.add(new Attribute(ATTR_TASK_STATE_FOR_NONZERO_EXIT_CODE,
           taskStateForNonZeroExitCode));
    }

    if (workingDirectory != null)
    {
      attrList.add(new Attribute(ATTR_WORKING_DIRECTORY, workingDirectory));
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
         PROPERTY_COMMAND_PATH, PROPERTY_COMMAND_ARGUMENTS,
         PROPERTY_COMMAND_OUTPUT_FILE, PROPERTY_LOG_COMMAND_OUTPUT,
         PROPERTY_TASK_STATE_FOR_NONZERO_EXIT_CODE,
         PROPERTY_WORKING_DIRECTORY));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty, List<Object>> props =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(
              StaticUtils.computeMapCapacity(6)));

    props.put(PROPERTY_COMMAND_PATH,
         Collections.<Object>singletonList(commandPath));

    if (commandArguments != null)
    {
      props.put(PROPERTY_COMMAND_ARGUMENTS,
           Collections.<Object>singletonList(commandArguments));
    }

    if (commandOutputFile != null)
    {
      props.put(PROPERTY_COMMAND_OUTPUT_FILE,
           Collections.<Object>singletonList(commandOutputFile));
    }

    if (logCommandOutput != null)
    {
      props.put(PROPERTY_LOG_COMMAND_OUTPUT,
           Collections.<Object>singletonList(logCommandOutput));
    }

    if (taskStateForNonZeroExitCode != null)
    {
      props.put(PROPERTY_TASK_STATE_FOR_NONZERO_EXIT_CODE,
           Collections.<Object>singletonList(taskStateForNonZeroExitCode));
    }

    if (workingDirectory != null)
    {
      props.put(PROPERTY_WORKING_DIRECTORY,
           Collections.<Object>singletonList(workingDirectory));
    }

    return Collections.unmodifiableMap(props);
  }
}
