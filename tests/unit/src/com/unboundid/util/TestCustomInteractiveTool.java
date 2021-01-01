/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a command-line tool implementation that has a custom
 * interactive mode.  The tool simply prints a specified message to standard
 * output, but the interactive mode will use a default message.
 */
public final class TestCustomInteractiveTool
       extends CommandLineTool
{
  // A reference to the completion message for this tool.
  private final AtomicReference<String> completionMessage;

  // The argument used to specify the message to write.
  private volatile StringArgument messageArg;



  /**
   * Runs this tool with the provided set of arguments.  It will use the JVM's
   * default standard output and standard error strings.
   *
   * @param  args  The command-line arguments to provide to this tool.
   */
  public static void main(final String... args)
  {
    final ResultCode exitCode = main(System.out, System.err, args);
    if (exitCode != ResultCode.SUCCESS)
    {
      System.exit(exitCode.intValue());
    }
  }



  /**
   * Runs this tool with the provided set of arguments and the given output and
   * error streams.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments to provide to this tool.
   *
   * @return  A result code that indicates the state of the tool.
   */
  public static ResultCode main(final OutputStream out, final OutputStream err,
                                final String... args)
  {
    final TestCustomInteractiveTool tool =
         new TestCustomInteractiveTool(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public TestCustomInteractiveTool(final OutputStream out,
                                   final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();
    messageArg = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "test-custom-interactive-tool";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return "Writes a specified message to standard output.";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> requestToolArgumentsInteractively(
                              final ArgumentParser parser)
  {
    return Arrays.asList("--message", "default message");
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected String getToolCompletionMessage()
  {
    return completionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    messageArg = new StringArgument(null, "message", true, 1, "{text}",
         "The message to be written.");
    parser.addArgument(messageArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    out(messageArg.getValue());
    return ResultCode.SUCCESS;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleUsages =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    exampleUsages.put(
         new String[] { "--message", "Hello, World!" },
         "Writes the message 'Hello, World!' to standard output.");

    return exampleUsages;
  }
}
