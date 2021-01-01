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
import java.io.FileInputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a utility that can log information about the launch and
 * completion of a tool invocation.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ToolInvocationLogger
{
  /**
   * The format string that should be used to format log message timestamps.
   */
  @NotNull private static final String LOG_MESSAGE_DATE_FORMAT =
       "dd/MMM/yyyy:HH:mm:ss.SSS Z";

  /**
   * The name of a system property that can be used to specify an alternate
   * instance root path for testing purposes.
   */
  @NotNull static final String PROPERTY_TEST_INSTANCE_ROOT =
          ToolInvocationLogger.class.getName() + ".testInstanceRootPath";

  /**
   * Prevent this utility class from being instantiated.
   */
  private ToolInvocationLogger()
  {
    // No implementation is required.
  }



  /**
   * Retrieves an object with a set of information about the invocation logging
   * that should be performed for the specified tool, if any.
   *
   * @param  commandName      The name of the command (without any path
   *                          information) for the associated tool.  It must not
   *                          be {@code null}.
   * @param  logByDefault     Indicates whether the tool indicates that
   *                          invocation log messages should be generated for
   *                          the specified tool by default.  This may be
   *                          overridden by content in the
   *                          {@code tool-invocation-logging.properties} file,
   *                          but it will be used in the absence of the
   *                          properties file or if the properties file does not
   *                          specify whether logging should be performed for
   *                          the specified tool.
   * @param  toolErrorStream  A print stream that may be used to report
   *                          information about any problems encountered while
   *                          attempting to perform invocation logging.  It
   *                          must not be {@code null}.
   *
   * @return  An object with a set of information about the invocation logging
   *          that should be performed for the specified tool.  The
   *          {@link ToolInvocationLogDetails#logInvocation()} method may
   *          be used to determine whether invocation logging should be
   *          performed.
   */
  @NotNull()
  public static ToolInvocationLogDetails getLogMessageDetails(
              @NotNull final String commandName,
              final boolean logByDefault,
              @NotNull final PrintStream toolErrorStream)
  {
    // Try to figure out the path to the server instance root.  In production
    // code, we'll look for an INSTANCE_ROOT environment variable to specify
    // that path, but to facilitate unit testing, we'll allow it to be
    // overridden by a Java system property so that we can have our own custom
    // path.
    String instanceRootPath =
         StaticUtils.getSystemProperty(PROPERTY_TEST_INSTANCE_ROOT);
    if (instanceRootPath == null)
    {
      instanceRootPath = StaticUtils.getEnvironmentVariable("INSTANCE_ROOT");
      if (instanceRootPath == null)
      {
        return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
      }
    }

    final File instanceRootDirectory =
         new File(instanceRootPath).getAbsoluteFile();
    if ((!instanceRootDirectory.exists()) ||
         (!instanceRootDirectory.isDirectory()))
    {
      return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
    }


    // Construct the paths to the default tool invocation log file and to the
    // logging properties file.
    final boolean canUseDefaultLog;
    final File defaultToolInvocationLogFile = StaticUtils.constructPath(
         instanceRootDirectory, "logs", "tools", "tool-invocation.log");
    if (defaultToolInvocationLogFile.exists())
    {
      canUseDefaultLog = defaultToolInvocationLogFile.isFile();
    }
    else
    {
      final File parentDirectory = defaultToolInvocationLogFile.getParentFile();
      canUseDefaultLog =
           (parentDirectory.exists() && parentDirectory.isDirectory());
    }

    final File invocationLoggingPropertiesFile = StaticUtils.constructPath(
         instanceRootDirectory, "config", "tool-invocation-logging.properties");


    // If the properties file doesn't exist, then just use the logByDefault
    // setting in conjunction with the default tool invocation log file.
    if (!invocationLoggingPropertiesFile.exists())
    {
      if (logByDefault && canUseDefaultLog)
      {
        return ToolInvocationLogDetails.createLogDetails(commandName, null,
             Collections.singleton(defaultToolInvocationLogFile),
             toolErrorStream);
      }
      else
      {
        return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
      }
    }


    // Load the properties file.  If this fails, then report an error and do not
    // attempt any additional logging.
    final Properties loggingProperties = new Properties();
    try (FileInputStream inputStream =
              new FileInputStream(invocationLoggingPropertiesFile))
    {
      loggingProperties.load(inputStream);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      printError(
           ERR_TOOL_LOGGER_ERROR_LOADING_PROPERTIES_FILE.get(
                invocationLoggingPropertiesFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           toolErrorStream);
      return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
    }


    // See if there is a tool-specific property that indicates whether to
    // perform invocation logging for the tool.
    Boolean logInvocation = getBooleanProperty(
         commandName + ".log-tool-invocations", loggingProperties,
         invocationLoggingPropertiesFile, null, toolErrorStream);


    // If there wasn't a valid tool-specific property to indicate whether to
    // perform invocation logging, then see if there is a default property for
    // all tools.
    if (logInvocation == null)
    {
      logInvocation = getBooleanProperty("default.log-tool-invocations",
           loggingProperties, invocationLoggingPropertiesFile, null,
           toolErrorStream);
    }


    // If we still don't know whether to log the invocation, then use the
    // default setting for the tool.
    if (logInvocation == null)
    {
      logInvocation = logByDefault;
    }


    // If we shouldn't log the invocation, then return a "no log" result now.
    if (!logInvocation)
    {
      return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
    }


    // See if there is a tool-specific property that specifies a log file path.
    final Set<File> logFiles = new HashSet<>(StaticUtils.computeMapCapacity(2));
    final String toolSpecificLogFilePathPropertyName =
         commandName + ".log-file-path";
    final File toolSpecificLogFile = getLogFileProperty(
         toolSpecificLogFilePathPropertyName, loggingProperties,
         invocationLoggingPropertiesFile, instanceRootDirectory,
         toolErrorStream);
    if (toolSpecificLogFile != null)
    {
      logFiles.add(toolSpecificLogFile);
    }


    // See if the tool should be included in the default log file.
    if (getBooleanProperty(commandName + ".include-in-default-log",
         loggingProperties, invocationLoggingPropertiesFile, true,
         toolErrorStream))
    {
      // See if there is a property that specifies a default log file path.
      // Otherwise, try to use the default path that we constructed earlier.
      final String defaultLogFilePathPropertyName = "default.log-file-path";
      final File defaultLogFile = getLogFileProperty(
           defaultLogFilePathPropertyName, loggingProperties,
           invocationLoggingPropertiesFile, instanceRootDirectory,
           toolErrorStream);
      if (defaultLogFile != null)
      {
        logFiles.add(defaultLogFile);
      }
      else if (canUseDefaultLog)
      {
        logFiles.add(defaultToolInvocationLogFile);
      }
      else
      {
        printError(
             ERR_TOOL_LOGGER_NO_LOG_FILES.get(commandName,
                  invocationLoggingPropertiesFile.getAbsolutePath(),
                  toolSpecificLogFilePathPropertyName,
                  defaultLogFilePathPropertyName),
             toolErrorStream);
      }
    }


    // If the set of log files is empty, then don't log anything.  Otherwise, we
    // can and should perform invocation logging.
    if (logFiles.isEmpty())
    {
      return ToolInvocationLogDetails.createDoNotLogDetails(commandName);
    }
    else
    {
      return ToolInvocationLogDetails.createLogDetails(commandName, null,
           logFiles, toolErrorStream);
    }
  }



  /**
   * Retrieves the Boolean value of the specified property from the set of tool
   * properties.
   *
   * @param  propertyName        The name of the property to retrieve.
   * @param  properties          The set of tool properties.
   * @param  propertiesFilePath  The path to the properties file.
   * @param  defaultValue        The default value that should be returned if
   *                             the property isn't set or has an invalid value.
   * @param  toolErrorStream     A print stream that may be used to report
   *                             information about any problems encountered
   *                             while attempting to perform invocation logging.
   *                             It must not be {@code null}.
   *
   * @return  {@code true} if the specified property exists with a value of
   *          {@code true}, {@code false} if the specified property exists with
   *          a value of {@code false}, or the default value if the property
   *          doesn't exist or has a value that is neither {@code true} nor
   *          {@code false}.
   */
  @Nullable()
   private static Boolean getBooleanProperty(
                @NotNull final String propertyName,
                @NotNull final Properties properties,
                @NotNull final File propertiesFilePath,
                @Nullable final Boolean defaultValue,
                @NotNull final PrintStream toolErrorStream)
   {
     final String propertyValue = properties.getProperty(propertyName);
     if (propertyValue == null)
     {
       return defaultValue;
     }

     if (propertyValue.equalsIgnoreCase("true"))
     {
       return true;
     }
     else if (propertyValue.equalsIgnoreCase("false"))
     {
       return false;
     }
     else
     {
      printError(
           ERR_TOOL_LOGGER_CANNOT_PARSE_BOOLEAN_PROPERTY.get(propertyValue,
                propertyName, propertiesFilePath.getAbsolutePath()),
           toolErrorStream);
       return defaultValue;
     }
   }



  /**
   * Retrieves a file referenced by the specified property from the set of
   * tool properties.
   *
   * @param  propertyName           The name of the property to retrieve.
   * @param  properties             The set of tool properties.
   * @param  propertiesFilePath     The path to the properties file.
   * @param  instanceRootDirectory  The path to the server's instance root
   *                                directory.
   * @param  toolErrorStream        A print stream that may be used to report
   *                                information about any problems encountered
   *                                while attempting to perform invocation
   *                                logging.  It must not be {@code null}.
   *
   * @return  A file referenced by the specified property, or {@code null} if
   *          the property is not set or does not reference a valid path.
   */
  @Nullable()
  private static File getLogFileProperty(
               @NotNull final String propertyName,
               @NotNull final Properties properties,
               @NotNull final File propertiesFilePath,
               @Nullable final File instanceRootDirectory,
               @NotNull final PrintStream toolErrorStream)
  {
    final String propertyValue = properties.getProperty(propertyName);
    if (propertyValue == null)
    {
      return null;
    }

    final File absoluteFile;
    final File configuredFile = new File(propertyValue);
    if (configuredFile.isAbsolute())
    {
      absoluteFile = configuredFile;
    }
    else
    {
      absoluteFile = new File(instanceRootDirectory.getAbsolutePath() +
           File.separator + propertyValue);
    }

    if (absoluteFile.exists())
    {
      if (absoluteFile.isFile())
      {
        return absoluteFile;
      }
      else
      {
        printError(
             ERR_TOOL_LOGGER_PATH_NOT_FILE.get(propertyValue, propertyName,
                  propertiesFilePath.getAbsolutePath()),
             toolErrorStream);
      }
    }
    else
    {
      final File parentFile = absoluteFile.getParentFile();
      if (parentFile.exists() && parentFile.isDirectory())
      {
        return absoluteFile;
      }
      else
      {
        printError(
             ERR_TOOL_LOGGER_PATH_PARENT_MISSING.get(propertyValue,
                  propertyName, propertiesFilePath.getAbsolutePath(),
                  parentFile.getAbsolutePath()),
             toolErrorStream);
      }
    }

    return null;
  }



  /**
   * Logs a message about the launch of the specified tool.  This method must
   * acquire an exclusive lock on each log file before attempting to append any
   * data to it.
   *
   * @param  logDetails               The tool invocation log details object
   *                                  obtained from running the
   *                                  {@link #getLogMessageDetails} method.  It
   *                                  must not be {@code null}.
   * @param  commandLineArguments     A list of the name-value pairs for any
   *                                  command-line arguments provided when
   *                                  running the program.  This must not be
   *                                  {@code null}, but it may be empty.
   *                                  <BR><BR>
   *                                  For a tool run in interactive mode, this
   *                                  should be the arguments that would have
   *                                  been provided if the tool had been invoked
   *                                  non-interactively.  For any arguments that
   *                                  have a name but no value (including
   *                                  Boolean arguments and subcommand names),
   *                                  or for unnamed trailing arguments, the
   *                                  first item in the pair should be
   *                                  non-{@code null} and the second item
   *                                  should be {@code null}.  For arguments
   *                                  whose values may contain sensitive
   *                                  information, the value should have already
   *                                  been replaced with the string
   *                                  "*****REDACTED*****".
   * @param  propertiesFileArguments  A list of the name-value pairs for any
   *                                  arguments obtained from a properties file
   *                                  rather than being supplied on the command
   *                                  line.  This must not be {@code null}, but
   *                                  may be empty.  The same constraints
   *                                  specified for the
   *                                  {@code commandLineArguments} parameter
   *                                  also apply to this parameter.
   * @param  propertiesFilePath       The path to the properties file from which
   *                                  the {@code propertiesFileArguments} values
   *                                  were obtained.
   */
  public static void logLaunchMessage(
          @NotNull final ToolInvocationLogDetails logDetails,
          @NotNull final List<ObjectPair<String,String>> commandLineArguments,
          @NotNull final List<ObjectPair<String,String>>
               propertiesFileArguments,
          @NotNull final String propertiesFilePath)
  {
    // Build the log message.
    final StringBuilder msgBuffer = new StringBuilder();
    final SimpleDateFormat dateFormat =
         new SimpleDateFormat(LOG_MESSAGE_DATE_FORMAT);

    msgBuffer.append("# [");
    msgBuffer.append(dateFormat.format(new Date()));
    msgBuffer.append(']');
    msgBuffer.append(StaticUtils.EOL);
    msgBuffer.append("# Command Name: ");
    msgBuffer.append(logDetails.getCommandName());
    msgBuffer.append(StaticUtils.EOL);
    msgBuffer.append("# Invocation ID: ");
    msgBuffer.append(logDetails.getInvocationID());
    msgBuffer.append(StaticUtils.EOL);

    final String systemUserName = StaticUtils.getSystemProperty("user.name");
    if ((systemUserName != null) && (! systemUserName.isEmpty()))
    {
      msgBuffer.append("# System User: ");
      msgBuffer.append(systemUserName);
      msgBuffer.append(StaticUtils.EOL);
    }

    if (! propertiesFileArguments.isEmpty())
    {
      msgBuffer.append("# Arguments obtained from '");
      msgBuffer.append(propertiesFilePath);
      msgBuffer.append("':");
      msgBuffer.append(StaticUtils.EOL);

      for (final ObjectPair<String,String> argPair : propertiesFileArguments)
      {
        msgBuffer.append("#      ");

        final String name = argPair.getFirst();
        if (name.startsWith("-"))
        {
          msgBuffer.append(name);
        }
        else
        {
          msgBuffer.append(StaticUtils.cleanExampleCommandLineArgument(name));
        }

        final String value = argPair.getSecond();
        if (value != null)
        {
          msgBuffer.append(' ');
          msgBuffer.append(getCleanArgumentValue(name, value));
        }

        msgBuffer.append(StaticUtils.EOL);
      }
    }

    msgBuffer.append(logDetails.getCommandName());
    for (final ObjectPair<String,String> argPair : commandLineArguments)
    {
      msgBuffer.append(' ');

      final String name = argPair.getFirst();
      if (name.startsWith("-"))
      {
        msgBuffer.append(name);
      }
      else
      {
        msgBuffer.append(StaticUtils.cleanExampleCommandLineArgument(name));
      }

      final String value = argPair.getSecond();
      if (value != null)
      {
        msgBuffer.append(' ');
        msgBuffer.append(getCleanArgumentValue(name, value));
      }
    }
    msgBuffer.append(StaticUtils.EOL);
    msgBuffer.append(StaticUtils.EOL);

    final byte[] logMessageBytes = StaticUtils.getBytes(msgBuffer.toString());


    // Append the log message to each of the log files.
    for (final File logFile : logDetails.getLogFiles())
    {
      logMessageToFile(logMessageBytes, logFile,
           logDetails.getToolErrorStream());
    }
  }



  /**
   * Retrieves a cleaned and possibly redacted version of the provided argument
   * value.
   *
   * @param  name   The name for the argument.  It must not be {@code null}.
   * @param  value  The value for the argument.  It must not be {@code null}.
   *
   * @return  A cleaned and possibly redacted version of the provided argument
   *          value.
   */
  @NotNull()
  private static String getCleanArgumentValue(@NotNull final String name,
                                              @NotNull final String value)
  {
    final String lowerName = StaticUtils.toLowerCase(name);
    if (lowerName.contains("password") ||
       lowerName.contains("passphrase") ||
       lowerName.endsWith("-pin") ||
       name.endsWith("Pin") ||
       name.endsWith("PIN"))
    {
      if (! (lowerName.contains("passwordfile") ||
           lowerName.contains("password-file") ||
           lowerName.contains("passwordpath") ||
           lowerName.contains("password-path") ||
           lowerName.contains("passphrasefile") ||
           lowerName.contains("passphrase-file") ||
           lowerName.contains("passphrasepath") ||
           lowerName.contains("passphrase-path")))
      {
        if (! StaticUtils.toLowerCase(value).contains("redacted"))
        {
          return "'*****REDACTED*****'";
        }
      }
    }

    return StaticUtils.cleanExampleCommandLineArgument(value);
  }



  /**
   * Logs a message about the completion of the specified tool.  This method
   * must acquire an exclusive lock on each log file before attempting to append
   * any data to it.
   *
   * @param  logDetails   The tool invocation log details object obtained from
   *                      running the {@link #getLogMessageDetails} method.  It
   *                      must not be {@code null}.
   * @param  exitCode     An integer exit code that may be used to broadly
   *                      indicate whether the tool completed successfully.  A
   *                      value of zero typically indicates that it did
   *                      complete successfully, while a nonzero value generally
   *                      indicates that some error occurred.  This may be
   *                      {@code null} if the tool did not complete normally
   *                      (for example, because the tool processing was
   *                      interrupted by a JVM shutdown).
   * @param  exitMessage  An optional message that provides information about
   *                      the completion of the tool processing.  It may be
   *                      {@code null} if no such message is available.
   */
  public static void logCompletionMessage(
                          @NotNull final ToolInvocationLogDetails logDetails,
                          @Nullable final Integer exitCode,
                          @Nullable final String exitMessage)
  {
    // Build the log message.
    final StringBuilder msgBuffer = new StringBuilder();
    final SimpleDateFormat dateFormat =
         new SimpleDateFormat(LOG_MESSAGE_DATE_FORMAT);

    msgBuffer.append("# [");
    msgBuffer.append(dateFormat.format(new Date()));
    msgBuffer.append(']');
    msgBuffer.append(StaticUtils.EOL);
    msgBuffer.append("# Command Name: ");
    msgBuffer.append(logDetails.getCommandName());
    msgBuffer.append(StaticUtils.EOL);
    msgBuffer.append("# Invocation ID: ");
    msgBuffer.append(logDetails.getInvocationID());
    msgBuffer.append(StaticUtils.EOL);

    if (exitCode != null)
    {
      msgBuffer.append("# Exit Code: ");
      msgBuffer.append(exitCode);
      msgBuffer.append(StaticUtils.EOL);
    }

    if (exitMessage != null)
    {
      msgBuffer.append("# Exit Message: ");
      cleanMessage(exitMessage, msgBuffer);
      msgBuffer.append(StaticUtils.EOL);
    }

    msgBuffer.append(StaticUtils.EOL);

    final byte[] logMessageBytes = StaticUtils.getBytes(msgBuffer.toString());


    // Append the log message to each of the log files.
    for (final File logFile : logDetails.getLogFiles())
    {
      logMessageToFile(logMessageBytes, logFile,
           logDetails.getToolErrorStream());
    }
  }



  /**
   * Writes a clean representation of the provided message to the given buffer.
   * All ASCII characters from the space to the tilde will be preserved.  All
   * other characters will use the hexadecimal representation of the bytes that
   * make up that character, with each pair of hexadecimal digits escaped with a
   * backslash.
   *
   * @param  message  The message to be cleaned.
   * @param  buffer   The buffer to which the message should be appended.
   */
  private static void cleanMessage(@NotNull final String message,
                                   @NotNull final StringBuilder buffer)
  {
    for (final char c : message.toCharArray())
    {
      if ((c >= ' ') && (c <= '~'))
      {
        buffer.append(c);
      }
      else
      {
        for (final byte b : StaticUtils.getBytes(Character.toString(c)))
        {
          buffer.append('\\');
          StaticUtils.toHex(b, buffer);
        }
      }
    }
  }



  /**
   * Acquires an exclusive lock on the specified log file and appends the
   * provided log message to it.
   *
   * @param  logMessageBytes  The bytes that comprise the log message to be
   *                          appended to the log file.
   * @param  logFile          The log file to be locked and updated.
   * @param  toolErrorStream  A print stream that may be used to report
   *                          information about any problems encountered while
   *                          attempting to perform invocation logging.  It
   *                          must not be {@code null}.
   */
  private static void logMessageToFile(@NotNull final byte[] logMessageBytes,
               @NotNull final File logFile,
               @NotNull final PrintStream toolErrorStream)
  {
    // Open a file channel for the target log file.
    final Set<StandardOpenOption> openOptionsSet = EnumSet.of(
            StandardOpenOption.CREATE, // Create the file if it doesn't exist.
            StandardOpenOption.APPEND, // Append to file if it already exists.
            StandardOpenOption.DSYNC); // Synchronously flush file on writing.

    final FileAttribute<?>[] fileAttributes;
    if (StaticUtils.isWindows())
    {
      fileAttributes = new FileAttribute<?>[0];
    }
    else
    {
      final Set<PosixFilePermission> filePermissionsSet = EnumSet.of(
              PosixFilePermission.OWNER_READ,   // Grant owner read access.
              PosixFilePermission.OWNER_WRITE); // Grant owner write access.
      final FileAttribute<Set<PosixFilePermission>> filePermissionsAttribute =
              PosixFilePermissions.asFileAttribute(filePermissionsSet);
      fileAttributes = new FileAttribute<?>[] { filePermissionsAttribute };
    }

    try (FileChannel fileChannel =
              FileChannel.open(logFile.toPath(), openOptionsSet,
                   fileAttributes))
    {
      try (FileLock fileLock =
                acquireFileLock(fileChannel, logFile, toolErrorStream))
      {
        if (fileLock != null)
        {
          try
          {
            fileChannel.write(ByteBuffer.wrap(logMessageBytes));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            printError(
                 ERR_TOOL_LOGGER_ERROR_WRITING_LOG_MESSAGE.get(
                      logFile.getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)),
                 toolErrorStream);
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      printError(
           ERR_TOOL_LOGGER_ERROR_OPENING_LOG_FILE.get(logFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           toolErrorStream);
    }
  }



  /**
   * Attempts to acquire an exclusive file lock on the provided file channel.
   *
   * @param  fileChannel      The file channel on which to acquire the file
   *                          lock.
   * @param  logFile          The path to the log file being locked.
   * @param  toolErrorStream  A print stream that may be used to report
   *                          information about any problems encountered while
   *                          attempting to perform invocation logging.  It
   *                          must not be {@code null}.
   *
   * @return  The file lock that was acquired, or {@code null} if the lock could
   *          not be acquired.
   */
  @Nullable()
  private static FileLock acquireFileLock(
               @NotNull final FileChannel fileChannel,
               @NotNull final File logFile,
               @NotNull final PrintStream toolErrorStream)
  {
    try
    {
      final FileLock fileLock = fileChannel.tryLock();
      if (fileLock != null)
      {
        return fileLock;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    int numAttempts = 1;
    final long stopWaitingTime = System.currentTimeMillis() + 1000L;
    while (System.currentTimeMillis() <= stopWaitingTime)
    {
      try
      {
        Thread.sleep(10L);
        final FileLock fileLock = fileChannel.tryLock();
        if (fileLock != null)
        {
          return fileLock;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      numAttempts++;
    }

    printError(
         ERR_TOOL_LOGGER_UNABLE_TO_ACQUIRE_FILE_LOCK.get(
              logFile.getAbsolutePath(), numAttempts),
         toolErrorStream);
    return null;
  }



  /**
   * Prints the provided message using the tool output stream.  The message will
   * be wrapped across multiple lines if necessary, and each line will be
   * prefixed with the octothorpe character (#) so that it is likely to be
   * interpreted as a comment by anything that tries to parse the tool output.
   *
   * @param  message          The message to be written.
   * @param  toolErrorStream  The print stream that should be used to write the
   *                          message.
   */
  private static void printError(@NotNull final String message,
                                 @NotNull final PrintStream toolErrorStream)
  {
    toolErrorStream.println();

    final int maxWidth = StaticUtils.TERMINAL_WIDTH_COLUMNS - 3;
    for (final String line : StaticUtils.wrapLine(message, maxWidth))
    {
      toolErrorStream.println("# " + line);
    }
  }
}
