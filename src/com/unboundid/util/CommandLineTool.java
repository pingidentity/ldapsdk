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
package com.unboundid.util;



import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentHelper;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolInvocationLogger;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolInvocationLogDetails;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolInvocationLogShutdownHook;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a framework for developing command-line tools that use
 * the argument parser provided as part of the UnboundID LDAP SDK for Java.
 * This tool adds a "-H" or "--help" option, which can be used to display usage
 * information for the program, and may also add a "-V" or "--version" option,
 * which can display the tool version.
 * <BR><BR>
 * Subclasses should include their own {@code main} method that creates an
 * instance of a {@code CommandLineTool} and should invoke the
 * {@link CommandLineTool#runTool} method with the provided arguments.  For
 * example:
 * <PRE>
 *   public class ExampleCommandLineTool
 *          extends CommandLineTool
 *   {
 *     public static void main(String[] args)
 *     {
 *       ExampleCommandLineTool tool = new ExampleCommandLineTool();
 *       ResultCode resultCode = tool.runTool(args);
 *       if (resultCode != ResultCode.SUCCESS)
 *       {
 *         System.exit(resultCode.intValue());
 *       }
 *     }
 *
 *     public ExampleCommandLineTool()
 *     {
 *       super(System.out, System.err);
 *     }
 *
 *     // The rest of the tool implementation goes here.
 *     ...
 *   }
 * </PRE>.
 * <BR><BR>
 * Note that in general, methods in this class are not threadsafe.  However, the
 * {@link #out(Object...)} and {@link #err(Object...)} methods may be invoked
 * concurrently by any number of threads.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class CommandLineTool
{
  // The argument used to indicate that the tool should append to the output
  // file rather than overwrite it.
  @Nullable private BooleanArgument appendToOutputFileArgument = null;

  // The argument used to request tool help.
  @Nullable private BooleanArgument helpArgument = null;

  // The argument used to request help about SASL authentication.
  @Nullable private BooleanArgument helpSASLArgument = null;

  // The argument used to request help information about all of the subcommands.
  @Nullable private BooleanArgument helpSubcommandsArgument = null;

  // The argument used to request interactive mode.
  @Nullable private BooleanArgument interactiveArgument = null;

  // The argument used to indicate that output should be written to standard out
  // as well as the specified output file.
  @Nullable private BooleanArgument teeOutputArgument = null;

  // The argument used to request the tool version.
  @Nullable private BooleanArgument versionArgument = null;

  // The argument used to specify the output file for standard output and
  // standard error.
  @Nullable private FileArgument outputFileArgument = null;

  // A list of arguments that can be used to enable SSL/TLS debugging.
  @NotNull private final List<BooleanArgument> enableSSLDebuggingArguments;

  // The password file reader for this tool.
  @NotNull private final PasswordFileReader passwordFileReader;

  // The print stream that was originally used for standard output.  It may not
  // be the current standard output stream if an output file has been
  // configured.
  @NotNull  private final PrintStream originalOut;

  // The print stream that was originally used for standard error.  It may not
  // be the current standard error stream if an output file has been configured.
  @NotNull private final PrintStream originalErr;

  // The print stream to use for messages written to standard output.
  @NotNull private volatile PrintStream out;

  // The print stream to use for messages written to standard error.
  @NotNull private volatile PrintStream err;



  /**
   * Creates a new instance of this command-line tool with the provided
   * information.
   *
   * @param  outStream  The output stream to use for standard output.  It may be
   *                    {@code System.out} for the JVM's default standard output
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   * @param  errStream  The output stream to use for standard error.  It may be
   *                    {@code System.err} for the JVM's default standard error
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   */
  public CommandLineTool(@Nullable final OutputStream outStream,
                         @Nullable final OutputStream errStream)
  {
    if (outStream == null)
    {
      out = NullOutputStream.getPrintStream();
    }
    else
    {
      out = new PrintStream(outStream);
    }

    if (errStream == null)
    {
      err = NullOutputStream.getPrintStream();
    }
    else
    {
      err = new PrintStream(errStream);
    }

    originalOut = out;
    originalErr = err;

    passwordFileReader = new PasswordFileReader(out, err);
    enableSSLDebuggingArguments = new ArrayList<>(1);
  }



  /**
   * Performs all processing for this command-line tool.  This includes:
   * <UL>
   *   <LI>Creating the argument parser and populating it using the
   *       {@link #addToolArguments} method.</LI>
   *   <LI>Parsing the provided set of command line arguments, including any
   *       additional validation using the {@link #doExtendedArgumentValidation}
   *       method.</LI>
   *   <LI>Invoking the {@link #doToolProcessing} method to do the appropriate
   *       work for this tool.</LI>
   * </UL>
   *
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  The result of processing this tool.  It should be
   *          {@link ResultCode#SUCCESS} if the tool completed its work
   *          successfully, or some other result if a problem occurred.
   */
  @NotNull()
  public final ResultCode runTool(@Nullable final String... args)
  {
    final ArgumentParser parser;
    try
    {
      parser = createArgumentParser();
      boolean exceptionFromParsingWithNoArgumentsExplicitlyProvided = false;
      if (supportsInteractiveMode() && defaultsToInteractiveMode() &&
          ((args == null) || (args.length == 0)))
      {
        // We'll go ahead and perform argument parsing even though no arguments
        // were provided because there might be a properties file that should
        // prevent running in interactive mode.  But we'll ignore any exception
        // thrown during argument parsing because the tool might require
        // arguments when run non-interactively.
        try
        {
          parser.parse(StaticUtils.NO_STRINGS);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          exceptionFromParsingWithNoArgumentsExplicitlyProvided = true;
        }
      }
      else if (args == null)
      {
        parser.parse(StaticUtils.NO_STRINGS);
      }
      else
      {
        parser.parse(args);
      }

      final File generatedPropertiesFile = parser.getGeneratedPropertiesFile();
      if (supportsPropertiesFile() && (generatedPropertiesFile != null))
      {
        wrapOut(0, StaticUtils.TERMINAL_WIDTH_COLUMNS - 1,
             INFO_CL_TOOL_WROTE_PROPERTIES_FILE.get(
                  generatedPropertiesFile.getAbsolutePath()));
        return ResultCode.SUCCESS;
      }

      if (helpArgument.isPresent())
      {
        out(parser.getUsageString(StaticUtils.TERMINAL_WIDTH_COLUMNS - 1));
        displayExampleUsages(parser);
        return ResultCode.SUCCESS;
      }

      if ((helpSASLArgument != null) && helpSASLArgument.isPresent())
      {
        String mechanism = null;
        final Argument saslOptionArgument =
             parser.getNamedArgument("saslOption");
        if ((saslOptionArgument != null) && saslOptionArgument.isPresent())
        {
          for (final String value :
               saslOptionArgument.getValueStringRepresentations(false))
          {
            final String lowerValue = StaticUtils.toLowerCase(value);
            if (lowerValue.startsWith("mech="))
            {
              final String mech = value.substring(5).trim();
              if (! mech.isEmpty())
              {
                mechanism = mech;
                break;
              }
            }
          }
        }


        out(SASLUtils.getUsageString(mechanism,
             StaticUtils.TERMINAL_WIDTH_COLUMNS - 1));
        return ResultCode.SUCCESS;
      }

      if ((helpSubcommandsArgument != null) &&
          helpSubcommandsArgument.isPresent())
      {
        final TreeMap<String,SubCommand> subCommands =
             getSortedSubCommands(parser);
        for (final SubCommand sc : subCommands.values())
        {
          final StringBuilder nameBuffer = new StringBuilder();

          final Iterator<String> nameIterator = sc.getNames(false).iterator();
          while (nameIterator.hasNext())
          {
            nameBuffer.append(nameIterator.next());
            if (nameIterator.hasNext())
            {
              nameBuffer.append(", ");
            }
          }
          out(nameBuffer.toString());

          for (final String descriptionLine :
               StaticUtils.wrapLine(sc.getDescription(),
                    (StaticUtils.TERMINAL_WIDTH_COLUMNS - 3)))
          {
            out("  " + descriptionLine);
          }
          out();
        }

        wrapOut(0, (StaticUtils.TERMINAL_WIDTH_COLUMNS - 1),
             INFO_CL_TOOL_USE_SUBCOMMAND_HELP.get(getToolName()));
        return ResultCode.SUCCESS;
      }

      if ((versionArgument != null) && versionArgument.isPresent())
      {
        out(getToolVersion());
        return ResultCode.SUCCESS;
      }

      // If we should enable SSL/TLS debugging, then do that now.  Do it before
      // any kind of user-defined validation is performed.  Java is really
      // touchy about when this is done, and we need to do it before any
      // connection attempt is made.
      for (final BooleanArgument a : enableSSLDebuggingArguments)
      {
        if (a.isPresent())
        {
          StaticUtils.setSystemProperty("javax.net.debug", "all");
        }
      }

      boolean extendedValidationDone = false;
      if (interactiveArgument != null)
      {
        if (interactiveArgument.isPresent() ||
            (defaultsToInteractiveMode() &&
             ((args == null) || (args.length == 0)) &&
             (parser.getArgumentsSetFromPropertiesFile().isEmpty() ||
                  exceptionFromParsingWithNoArgumentsExplicitlyProvided)))
        {
          try
          {
            final List<String> interactiveArgs =
                 requestToolArgumentsInteractively(parser);
            if (interactiveArgs == null)
            {
              final CommandLineToolInteractiveModeProcessor processor =
                   new CommandLineToolInteractiveModeProcessor(this, parser);
              processor.doInteractiveModeProcessing();
              extendedValidationDone = true;
            }
            else
            {
              ArgumentHelper.reset(parser);
              parser.parse(StaticUtils.toArray(interactiveArgs, String.class));
            }
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);

            final String message = le.getMessage();
            if ((message != null) && (! message.isEmpty()))
            {
              err(message);
            }

            return le.getResultCode();
          }
        }
      }

      if (! extendedValidationDone)
      {
        doExtendedArgumentValidation();
      }
    }
    catch (final ArgumentException ae)
    {
      Debug.debugException(ae);
      err(ae.getMessage());
      return ResultCode.PARAM_ERROR;
    }

    PrintStream outputFileStream = null;
    if ((outputFileArgument != null) && outputFileArgument.isPresent())
    {
      final File outputFile = outputFileArgument.getValue();
      final boolean append = ((appendToOutputFileArgument != null) &&
           appendToOutputFileArgument.isPresent());

      try
      {
        final FileOutputStream fos = new FileOutputStream(outputFile, append);
        outputFileStream = new PrintStream(fos, true, "UTF-8");
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err(ERR_CL_TOOL_ERROR_CREATING_OUTPUT_FILE.get(
             outputFile.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }

      if ((teeOutputArgument != null) && teeOutputArgument.isPresent())
      {
        out = new PrintStream(new TeeOutputStream(out, outputFileStream));
        err = new PrintStream(new TeeOutputStream(err, outputFileStream));
      }
      else
      {
        out = outputFileStream;
        err = outputFileStream;
      }
    }

    try
    {
      // If any values were selected using a properties file, then display
      // information about them.
      final List<String> argsSetFromPropertiesFiles =
           parser.getArgumentsSetFromPropertiesFile();
      if ((! argsSetFromPropertiesFiles.isEmpty()) &&
          (! parser.suppressPropertiesFileComment()))
      {
        for (final String line :
             StaticUtils.wrapLine(
                  INFO_CL_TOOL_ARGS_FROM_PROPERTIES_FILE.get(
                       parser.getPropertiesFileUsed().getPath()),
                  (StaticUtils.TERMINAL_WIDTH_COLUMNS - 3)))
        {
          out("# ", line);
        }

        final StringBuilder buffer = new StringBuilder();
        for (final String s : argsSetFromPropertiesFiles)
        {
          if (s.startsWith("-"))
          {
            if (buffer.length() > 0)
            {
              out(buffer);
              buffer.setLength(0);
            }

            buffer.append("#      ");
            buffer.append(s);
          }
          else
          {
            if (buffer.length() == 0)
            {
              // This should never happen.
              buffer.append("#      ");
            }
            else
            {
              buffer.append(' ');
            }

            buffer.append(StaticUtils.cleanExampleCommandLineArgument(s));
          }
        }

        if (buffer.length() > 0)
        {
          out(buffer);
        }

        out();
      }


      CommandLineToolShutdownHook shutdownHook = null;
      final AtomicReference<ResultCode> exitCode = new AtomicReference<>();
      if (registerShutdownHook())
      {
        shutdownHook = new CommandLineToolShutdownHook(this, exitCode);
        Runtime.getRuntime().addShutdownHook(shutdownHook);
      }

      final ToolInvocationLogDetails logDetails =
              ToolInvocationLogger.getLogMessageDetails(
                      getToolName(), logToolInvocationByDefault(), getErr());
      ToolInvocationLogShutdownHook logShutdownHook = null;

      if (logDetails.logInvocation())
      {
        final HashSet<Argument> argumentsSetFromPropertiesFile =
             new HashSet<>(StaticUtils.computeMapCapacity(10));
        final ArrayList<ObjectPair<String,String>> propertiesFileArgList =
             new ArrayList<>(10);
        getToolInvocationPropertiesFileArguments(parser,
             argumentsSetFromPropertiesFile, propertiesFileArgList);

        final ArrayList<ObjectPair<String,String>> providedArgList =
             new ArrayList<>(10);
        getToolInvocationProvidedArguments(parser,
             argumentsSetFromPropertiesFile, providedArgList);

        logShutdownHook = new ToolInvocationLogShutdownHook(logDetails);
        Runtime.getRuntime().addShutdownHook(logShutdownHook);

        final String propertiesFilePath;
        if (propertiesFileArgList.isEmpty())
        {
          propertiesFilePath = "";
        }
        else
        {
          final File propertiesFile = parser.getPropertiesFileUsed();
          if (propertiesFile == null)
          {
            propertiesFilePath = "";
          }
          else
          {
            propertiesFilePath = propertiesFile.getAbsolutePath();
          }
        }

        ToolInvocationLogger.logLaunchMessage(logDetails, providedArgList,
                propertiesFileArgList, propertiesFilePath);
      }

      try
      {
        exitCode.set(doToolProcessing());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err(StaticUtils.getExceptionMessage(e));
        exitCode.set(ResultCode.LOCAL_ERROR);
      }
      finally
      {
        if (logShutdownHook != null)
        {
          Runtime.getRuntime().removeShutdownHook(logShutdownHook);

          String completionMessage = getToolCompletionMessage();
          if (completionMessage == null)
          {
            completionMessage = exitCode.get().getName();
          }

          ToolInvocationLogger.logCompletionMessage(
                  logDetails, exitCode.get().intValue(), completionMessage);
        }
        if (shutdownHook != null)
        {
          Runtime.getRuntime().removeShutdownHook(shutdownHook);
        }
      }

      return exitCode.get();
    }
    finally
    {
      if (outputFileStream != null)
      {
        outputFileStream.close();
      }
    }
  }



  /**
   * Updates the provided argument list with object pairs that comprise the
   * set of arguments actually provided to this tool on the command line.
   *
   * @param  parser                          The argument parser for this tool.
   *                                         It must not be {@code null}.
   * @param  argumentsSetFromPropertiesFile  A set that includes all arguments
   *                                         set from the properties file.
   * @param  argList                         The list to which the argument
   *                                         information should be added.  It
   *                                         must not be {@code null}.  The
   *                                         first element of each object pair
   *                                         that is added must be
   *                                         non-{@code null}.  The second
   *                                         element in any given pair may be
   *                                         {@code null} if the first element
   *                                         represents the name of an argument
   *                                         that doesn't take any values, the
   *                                         name of the selected subcommand, or
   *                                         an unnamed trailing argument.
   */
  private static void getToolInvocationProvidedArguments(
               @NotNull final ArgumentParser parser,
               @NotNull final Set<Argument> argumentsSetFromPropertiesFile,
               @NotNull final List<ObjectPair<String,String>> argList)
  {
    final String noValue = null;
    final SubCommand subCommand = parser.getSelectedSubCommand();
    if (subCommand != null)
    {
      argList.add(new ObjectPair<>(subCommand.getPrimaryName(), noValue));
    }

    for (final Argument arg : parser.getNamedArguments())
    {
      // Exclude arguments that weren't provided.
      if (! arg.isPresent())
      {
        continue;
      }

      // Exclude arguments that were set from the properties file.
      if (argumentsSetFromPropertiesFile.contains(arg))
      {
        continue;
      }

      if (arg.takesValue())
      {
        for (final String value : arg.getValueStringRepresentations(false))
        {
          if (arg.isSensitive())
          {
            argList.add(new ObjectPair<>(arg.getIdentifierString(),
                 "*****REDACTED*****"));
          }
          else
          {
            argList.add(new ObjectPair<>(arg.getIdentifierString(), value));
          }
        }
      }
      else
      {
        argList.add(new ObjectPair<>(arg.getIdentifierString(), noValue));
      }
    }

    if (subCommand != null)
    {
      getToolInvocationProvidedArguments(subCommand.getArgumentParser(),
           argumentsSetFromPropertiesFile, argList);
    }

    for (final String trailingArgument : parser.getTrailingArguments())
    {
      argList.add(new ObjectPair<>(trailingArgument, noValue));
    }
  }



  /**
   * Updates the provided argument list with object pairs that comprise the
   * set of tool arguments set from a properties file.
   *
   * @param  parser                          The argument parser for this tool.
   *                                         It must not be {@code null}.
   * @param  argumentsSetFromPropertiesFile  A set that should be updated with
   *                                         each argument set from the
   *                                         properties file.
   * @param  argList                         The list to which the argument
   *                                         information should be added.  It
   *                                         must not be {@code null}.  The
   *                                         first element of each object pair
   *                                         that is added must be
   *                                         non-{@code null}.  The second
   *                                         element in any given pair may be
   *                                         {@code null} if the first element
   *                                         represents the name of an argument
   *                                         that doesn't take any values, the
   *                                         name of the selected subcommand, or
   *                                         an unnamed trailing argument.
   */
  private static void getToolInvocationPropertiesFileArguments(
               @NotNull final ArgumentParser parser,
               @NotNull final Set<Argument> argumentsSetFromPropertiesFile,
               @NotNull final List<ObjectPair<String,String>> argList)
  {
    final ArgumentParser subCommandParser;
    final SubCommand subCommand = parser.getSelectedSubCommand();
    if (subCommand == null)
    {
      subCommandParser = null;
    }
    else
    {
      subCommandParser = subCommand.getArgumentParser();
    }

    final String noValue = null;

    final Iterator<String> iterator =
            parser.getArgumentsSetFromPropertiesFile().iterator();
    while (iterator.hasNext())
    {
      final String arg = iterator.next();
      if (arg.startsWith("-"))
      {
        Argument a;
        if (arg.startsWith("--"))
        {
          final String longIdentifier = arg.substring(2);
          a = parser.getNamedArgument(longIdentifier);
          if ((a == null) && (subCommandParser != null))
          {
            a = subCommandParser.getNamedArgument(longIdentifier);
          }
        }
        else
        {
          final char shortIdentifier = arg.charAt(1);
          a = parser.getNamedArgument(shortIdentifier);
          if ((a == null) && (subCommandParser != null))
          {
            a = subCommandParser.getNamedArgument(shortIdentifier);
          }
        }

        if (a != null)
        {
          argumentsSetFromPropertiesFile.add(a);

          if (a.takesValue())
          {
            final String value = iterator.next();
            if (a.isSensitive())
            {
              argList.add(new ObjectPair<>(a.getIdentifierString(), noValue));
            }
            else
            {
              argList.add(new ObjectPair<>(a.getIdentifierString(), value));
            }
          }
          else
          {
            argList.add(new ObjectPair<>(a.getIdentifierString(), noValue));
          }
        }
      }
      else
      {
        argList.add(new ObjectPair<>(arg, noValue));
      }
    }
  }



  /**
   * Retrieves a sorted map of subcommands for the provided argument parser,
   * alphabetized by primary name.
   *
   * @param  parser  The argument parser for which to get the sorted
   *                 subcommands.
   *
   * @return  The sorted map of subcommands.
   */
  @NotNull()
  private static TreeMap<String,SubCommand> getSortedSubCommands(
                      @NotNull final ArgumentParser parser)
  {
    final TreeMap<String,SubCommand> m = new TreeMap<>();
    for (final SubCommand sc : parser.getSubCommands())
    {
      m.put(sc.getPrimaryName(), sc);
    }
    return m;
  }



  /**
   * Writes example usage information for this tool to the standard output
   * stream.
   *
   * @param  parser  The argument parser used to process the provided set of
   *                 command-line arguments.
   */
  private void displayExampleUsages(@NotNull final ArgumentParser parser)
  {
    final LinkedHashMap<String[],String> examples;
    if ((parser != null) && (parser.getSelectedSubCommand() != null))
    {
      examples = parser.getSelectedSubCommand().getExampleUsages();
    }
    else
    {
      examples = getExampleUsages();
    }

    if ((examples == null) || examples.isEmpty())
    {
      return;
    }

    out(INFO_CL_TOOL_LABEL_EXAMPLES);

    final int wrapWidth = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;
    for (final Map.Entry<String[],String> e : examples.entrySet())
    {
      out();
      wrapOut(2, wrapWidth, e.getValue());
      out();

      final StringBuilder buffer = new StringBuilder();
      buffer.append("    ");
      buffer.append(getToolName());

      final String[] args = e.getKey();
      for (int i=0; i < args.length; i++)
      {
        buffer.append(' ');

        // If the argument has a value, then make sure to keep it on the same
        // line as the argument name.  This may introduce false positives due to
        // unnamed trailing arguments, but the worst that will happen that case
        // is that the output may be wrapped earlier than necessary one time.
        String arg = args[i];
        if (arg.startsWith("-"))
        {
          if ((i < (args.length - 1)) && (! args[i+1].startsWith("-")))
          {
            final ExampleCommandLineArgument cleanArg =
                ExampleCommandLineArgument.getCleanArgument(args[i+1]);
            arg += ' ' + cleanArg.getLocalForm();
            i++;
          }
        }
        else
        {
          final ExampleCommandLineArgument cleanArg =
              ExampleCommandLineArgument.getCleanArgument(arg);
          arg = cleanArg.getLocalForm();
        }

        if ((buffer.length() + arg.length() + 2) < wrapWidth)
        {
          buffer.append(arg);
        }
        else
        {
          buffer.append(StaticUtils.getCommandLineContinuationString());
          out(buffer.toString());
          buffer.setLength(0);
          buffer.append("         ");
          buffer.append(arg);
        }
      }

      out(buffer.toString());
    }
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @NotNull()
  public abstract String getToolName();



  /**
   * Retrieves a human-readable description for this tool.  If the description
   * should include multiple paragraphs, then this method should return the text
   * for the first paragraph, and the
   * {@link #getAdditionalDescriptionParagraphs()} method should be used to
   * return the text for the subsequent paragraphs.
   *
   * @return  A human-readable description for this tool.
   */
  @Nullable()
  public abstract String getToolDescription();



  /**
   * Retrieves additional paragraphs that should be included in the description
   * for this tool.  If the tool description should include multiple paragraphs,
   * then the {@link #getToolDescription()} method should return the text of the
   * first paragraph, and each item in the list returned by this method should
   * be the text for each subsequent paragraph.  If the tool description should
   * only have a single paragraph, then this method may return {@code null} or
   * an empty list.
   *
   * @return  Additional paragraphs that should be included in the description
   *          for this tool, or {@code null} or an empty list if only a single
   *          description paragraph (whose text is returned by the
   *          {@code getToolDescription} method) is needed.
   */
  @Nullable()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.emptyList();
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Nullable()
  public String getToolVersion()
  {
    return null;
  }



  /**
   * Retrieves the minimum number of unnamed trailing arguments that must be
   * provided for this tool.  If a tool requires the use of trailing arguments,
   * then it must override this method and the {@link #getMaxTrailingArguments}
   * arguments to return nonzero values, and it must also override the
   * {@link #getTrailingArgumentsPlaceholder} method to return a
   * non-{@code null} value.
   *
   * @return  The minimum number of unnamed trailing arguments that may be
   *          provided for this tool.  A value of zero indicates that the tool
   *          may be invoked without any trailing arguments.
   */
  public int getMinTrailingArguments()
  {
    return 0;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that may be
   * provided for this tool.  If a tool supports trailing arguments, then it
   * must override this method to return a nonzero value, and must also override
   * the {@link CommandLineTool#getTrailingArgumentsPlaceholder} method to
   * return a non-{@code null} value.
   *
   * @return  The maximum number of unnamed trailing arguments that may be
   *          provided for this tool.  A value of zero indicates that trailing
   *          arguments are not allowed.  A negative value indicates that there
   *          should be no limit on the number of trailing arguments.
   */
  public int getMaxTrailingArguments()
  {
    return 0;
  }



  /**
   * Retrieves a placeholder string that should be used for trailing arguments
   * in the usage information for this tool.
   *
   * @return  A placeholder string that should be used for trailing arguments in
   *          the usage information for this tool, or {@code null} if trailing
   *          arguments are not supported.
   */
  @Nullable()
  public String getTrailingArgumentsPlaceholder()
  {
    return null;
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  public boolean supportsInteractiveMode()
  {
    return false;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  public boolean defaultsToInteractiveMode()
  {
    return false;
  }



  /**
   * Interactively prompts the user for information needed to invoke this tool
   * and returns an appropriate list of arguments that should be used to run it.
   * <BR><BR>
   * This method will only be invoked if {@link #supportsInteractiveMode()}
   * returns {@code true}, and if one of the following conditions is satisfied:
   * <UL>
   *   <LI>The {@code --interactive} argument is explicitly provided on the
   *       command line.</LI>
   *   <LI>The tool was invoked without any command-line arguments and
   *       {@link #defaultsToInteractiveMode()} returns {@code true}.</LI>
   * </UL>
   * If this method is invoked and returns {@code null}, then the LDAP SDK's
   * default interactive mode processing will be performed.  Otherwise, the tool
   * will be invoked with only the arguments in the list that is returned.
   *
   * @param  parser  The argument parser that has been used to parse any
   *                 command-line arguments that were provided before the
   *                 interactive mode processing was invoked.  If this method
   *                 returns a non-{@code null} value, then this parser will be
   *                 reset before parsing the new set of arguments.
   *
   * @return  Retrieves a list of command-line arguments that may be used to
   *          invoke this tool, or {@code null} if the LDAP SDK's default
   *          interactive mode processing should be performed.
   *
   * @throws  LDAPException  If a problem is encountered while interactively
   *                         obtaining the arguments that should be used to
   *                         run the tool.
   */
  @Nullable()
  protected List<String> requestToolArgumentsInteractively(
                              @NotNull final ArgumentParser parser)
            throws LDAPException
  {
    // Fall back to using the LDAP SDK's default interactive mode processor.
    return null;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  public boolean supportsPropertiesFile()
  {
    return false;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  protected boolean supportsOutputFile()
  {
    return false;
  }



  /**
   * Indicates whether to log messages about the launch and completion of this
   * tool into the invocation log of Ping Identity server products that may
   * include it.  This method is not needed for tools that are not expected to
   * be part of the Ping Identity server products suite.  Further, this value
   * may be overridden by settings in the server's
   * tool-invocation-logging.properties file.
   * <BR><BR>
   * This method should generally return {@code true} for tools that may alter
   * the server configuration, data, or other state information, and
   * {@code false} for tools that do not make any changes.
   *
   * @return  {@code true} if Ping Identity server products should include
   *          messages about the launch and completion of this tool in tool
   *          invocation log files by default, or {@code false} if not.
   */
  protected boolean logToolInvocationByDefault()
  {
    return false;
  }



  /**
   * Retrieves an optional message that may provide additional information about
   * the way that the tool completed its processing.  For example if the tool
   * exited with an error message, it may be useful for this method to return
   * that error message.
   * <BR><BR>
   * The message returned by this method is intended for purposes and is not
   * meant to be parsed or programmatically interpreted.
   *
   * @return  An optional message that may provide additional information about
   *          the completion state for this tool, or {@code null} if no
   *          completion message is available.
   */
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return null;
  }



  /**
   * Creates a parser that can be used to to parse arguments accepted by
   * this tool.
   *
   * @return ArgumentParser that can be used to parse arguments for this
   *         tool.
   *
   * @throws ArgumentException  If there was a problem initializing the
   *                            parser for this tool.
   */
  @NotNull()
  public final ArgumentParser createArgumentParser()
         throws ArgumentException
  {
    final ArgumentParser parser = new ArgumentParser(getToolName(),
         getToolDescription(), getAdditionalDescriptionParagraphs(),
         getMinTrailingArguments(), getMaxTrailingArguments(),
         getTrailingArgumentsPlaceholder());
    parser.setCommandLineTool(this);

    addToolArguments(parser);

    if (supportsInteractiveMode())
    {
      interactiveArgument = new BooleanArgument(null, "interactive",
           INFO_CL_TOOL_DESCRIPTION_INTERACTIVE.get());
      interactiveArgument.setUsageArgument(true);
      parser.addArgument(interactiveArgument);
    }

    if (supportsOutputFile())
    {
      outputFileArgument = new FileArgument(null, "outputFile", false, 1, null,
           INFO_CL_TOOL_DESCRIPTION_OUTPUT_FILE.get(), false, true, true,
           false);
      outputFileArgument.addLongIdentifier("output-file", true);
      outputFileArgument.setUsageArgument(true);
      parser.addArgument(outputFileArgument);

      appendToOutputFileArgument = new BooleanArgument(null,
           "appendToOutputFile", 1,
           INFO_CL_TOOL_DESCRIPTION_APPEND_TO_OUTPUT_FILE.get(
                outputFileArgument.getIdentifierString()));
      appendToOutputFileArgument.addLongIdentifier("append-to-output-file",
           true);
      appendToOutputFileArgument.setUsageArgument(true);
      parser.addArgument(appendToOutputFileArgument);

      teeOutputArgument = new BooleanArgument(null, "teeOutput", 1,
           INFO_CL_TOOL_DESCRIPTION_TEE_OUTPUT.get(
                outputFileArgument.getIdentifierString()));
      teeOutputArgument.addLongIdentifier("tee-output", true);
      teeOutputArgument.setUsageArgument(true);
      parser.addArgument(teeOutputArgument);

      parser.addDependentArgumentSet(appendToOutputFileArgument,
           outputFileArgument);
      parser.addDependentArgumentSet(teeOutputArgument,
           outputFileArgument);
    }

    helpArgument = new BooleanArgument('H', "help",
         INFO_CL_TOOL_DESCRIPTION_HELP.get());
    helpArgument.addShortIdentifier('?', true);
    helpArgument.setUsageArgument(true);
    parser.addArgument(helpArgument);

    if (! parser.getSubCommands().isEmpty())
    {
      helpSubcommandsArgument = new BooleanArgument(null, "helpSubcommands", 1,
           INFO_CL_TOOL_DESCRIPTION_HELP_SUBCOMMANDS.get());
      helpSubcommandsArgument.addLongIdentifier("helpSubcommand", true);
      helpSubcommandsArgument.addLongIdentifier("help-subcommands", true);
      helpSubcommandsArgument.addLongIdentifier("help-subcommand", true);
      helpSubcommandsArgument.setUsageArgument(true);
      parser.addArgument(helpSubcommandsArgument);
    }

    final String version = getToolVersion();
    if ((version != null) && (! version.isEmpty()) &&
        (parser.getNamedArgument("version") == null))
    {
      final Character shortIdentifier;
      if (parser.getNamedArgument('V') == null)
      {
        shortIdentifier = 'V';
      }
      else
      {
        shortIdentifier = null;
      }

      versionArgument = new BooleanArgument(shortIdentifier, "version",
           INFO_CL_TOOL_DESCRIPTION_VERSION.get());
      versionArgument.setUsageArgument(true);
      parser.addArgument(versionArgument);
    }

    if (supportsPropertiesFile())
    {
      parser.enablePropertiesFileSupport();
    }

    return parser;
  }



  /**
   * Specifies the argument that is used to retrieve usage information about
   * SASL authentication.
   *
   * @param  helpSASLArgument  The argument that is used to retrieve usage
   *                           information about SASL authentication.
   */
  void setHelpSASLArgument(@NotNull final BooleanArgument helpSASLArgument)
  {
    this.helpSASLArgument = helpSASLArgument;
  }



  /**
   * Adds the provided argument to the set of arguments that may be used to
   * enable JVM SSL/TLS debugging.
   *
   * @param  enableSSLDebuggingArgument  The argument to add to the set of
   *                                     arguments that may be used to enable
   *                                     JVM SSL/TLS debugging.
   */
  protected void addEnableSSLDebuggingArgument(
                      @NotNull final BooleanArgument enableSSLDebuggingArgument)
  {
    enableSSLDebuggingArguments.add(enableSSLDebuggingArgument);
  }



  /**
   * Retrieves a set containing the long identifiers used for usage arguments
   * injected by this class.
   *
   * @param  tool  The tool to use to help make the determination.
   *
   * @return  A set containing the long identifiers used for usage arguments
   *          injected by this class.
   */
  @NotNull()
  static Set<String> getUsageArgumentIdentifiers(
                          @NotNull final CommandLineTool tool)
  {
    final LinkedHashSet<String> ids =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(9));

    ids.add("help");
    ids.add("version");
    ids.add("helpSubcommands");

    if (tool.supportsInteractiveMode())
    {
      ids.add("interactive");
    }

    if (tool.supportsPropertiesFile())
    {
      ids.add("propertiesFilePath");
      ids.add("generatePropertiesFile");
      ids.add("noPropertiesFile");
      ids.add("suppressPropertiesFileComment");
    }

    if (tool.supportsOutputFile())
    {
      ids.add("outputFile");
      ids.add("appendToOutputFile");
      ids.add("teeOutput");
    }

    return Collections.unmodifiableSet(ids);
  }



  /**
   * Adds the command-line arguments supported for use with this tool to the
   * provided argument parser.  The tool may need to retain references to the
   * arguments (and/or the argument parser, if trailing arguments are allowed)
   * to it in order to obtain their values for use in later processing.
   *
   * @param  parser  The argument parser to which the arguments are to be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding any of the
   *                             tool-specific arguments to the provided
   *                             argument parser.
   */
  public abstract void addToolArguments(@NotNull ArgumentParser parser)
         throws ArgumentException;



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and immediately
   * before the {@link CommandLineTool#doToolProcessing} method is invoked.
   * Note that if the tool supports interactive mode, then this method may be
   * invoked multiple times to allow the user to interactively fix validation
   * errors.
   *
   * @throws  ArgumentException  If there was a problem with the command-line
   *                             arguments provided to this program.
   */
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // No processing will be performed by default.
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  public abstract ResultCode doToolProcessing();



  /**
   * Indicates whether this tool should register a shutdown hook with the JVM.
   * Shutdown hooks allow for a best-effort attempt to perform a specified set
   * of processing when the JVM is shutting down under various conditions,
   * including:
   * <UL>
   *   <LI>When all non-daemon threads have stopped running (i.e., the tool has
   *       completed processing).</LI>
   *   <LI>When {@code System.exit()} or {@code Runtime.exit()} is called.</LI>
   *   <LI>When the JVM receives an external kill signal (e.g., via the use of
   *       the kill tool or interrupting the JVM with Ctrl+C).</LI>
   * </UL>
   * Shutdown hooks may not be invoked if the process is forcefully killed
   * (e.g., using "kill -9", or the {@code System.halt()} or
   * {@code Runtime.halt()} methods).
   * <BR><BR>
   * If this method is overridden to return {@code true}, then the
   * {@link #doShutdownHookProcessing(ResultCode)} method should also be
   * overridden to contain the logic that will be invoked when the JVM is
   * shutting down in a manner that calls shutdown hooks.
   *
   * @return  {@code true} if this tool should register a shutdown hook, or
   *          {@code false} if not.
   */
  protected boolean registerShutdownHook()
  {
    return false;
  }



  /**
   * Performs any processing that may be needed when the JVM is shutting down,
   * whether because tool processing has completed or because it has been
   * interrupted (e.g., by a kill or break signal).
   * <BR><BR>
   * Note that because shutdown hooks run at a delicate time in the life of the
   * JVM, they should complete quickly and minimize access to external
   * resources.  See the documentation for the
   * {@code java.lang.Runtime.addShutdownHook} method for recommendations and
   * restrictions about writing shutdown hooks.
   *
   * @param  resultCode  The result code returned by the tool.  It may be
   *                     {@code null} if the tool was interrupted before it
   *                     completed processing.
   */
  protected void doShutdownHookProcessing(@Nullable final ResultCode resultCode)
  {
    throw new LDAPSDKUsageException(
         ERR_COMMAND_LINE_TOOL_SHUTDOWN_HOOK_NOT_IMPLEMENTED.get(
              getToolName()));
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @Nullable()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    return null;
  }



  /**
   * Retrieves the password file reader for this tool, which may be used to
   * read passwords from (optionally compressed and encrypted) files.
   *
   * @return  The password file reader for this tool.
   */
  @NotNull()
  public final PasswordFileReader getPasswordFileReader()
  {
    return passwordFileReader;
  }



  /**
   * Retrieves the print stream that will be used for standard output.
   *
   * @return  The print stream that will be used for standard output.
   */
  @NotNull()
  public final PrintStream getOut()
  {
    return out;
  }



  /**
   * Retrieves the print stream that may be used to write to the original
   * standard output.  This may be different from the current standard output
   * stream if an output file has been configured.
   *
   * @return  The print stream that may be used to write to the original
   *          standard output.
   */
  @NotNull()
  public final PrintStream getOriginalOut()
  {
    return originalOut;
  }



  /**
   * Writes the provided message to the standard output stream for this tool.
   * <BR><BR>
   * This method is completely threadsafe and my be invoked concurrently by any
   * number of threads.
   *
   * @param  msg  The message components that will be written to the standard
   *              output stream.  They will be concatenated together on the same
   *              line, and that line will be followed by an end-of-line
   *              sequence.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final synchronized void out(@NotNull final Object... msg)
  {
    write(out, 0, 0, msg);
  }



  /**
   * Writes the provided message to the standard output stream for this tool,
   * optionally wrapping and/or indenting the text in the process.
   * <BR><BR>
   * This method is completely threadsafe and my be invoked concurrently by any
   * number of threads.
   *
   * @param  indent      The number of spaces each line should be indented.  A
   *                     value less than or equal to zero indicates that no
   *                     indent should be used.
   * @param  wrapColumn  The column at which to wrap long lines.  A value less
   *                     than or equal to two indicates that no wrapping should
   *                     be performed.  If both an indent and a wrap column are
   *                     to be used, then the wrap column must be greater than
   *                     the indent.
   * @param  msg         The message components that will be written to the
   *                     standard output stream.  They will be concatenated
   *                     together on the same line, and that line will be
   *                     followed by an end-of-line sequence.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final synchronized void wrapOut(final int indent, final int wrapColumn,
                                         @NotNull final Object... msg)
  {
    write(out, indent, wrapColumn, msg);
  }



  /**
   * Writes the provided message to the standard output stream for this tool,
   * optionally wrapping and/or indenting the text in the process.
   * <BR><BR>
   * This method is completely threadsafe and my be invoked concurrently by any
   * number of threads.
   *
   * @param  firstLineIndent       The number of spaces the first line should be
   *                               indented.  A value less than or equal to zero
   *                               indicates that no indent should be used.
   * @param  subsequentLineIndent  The number of spaces each line except the
   *                               first should be indented.  A value less than
   *                               or equal to zero indicates that no indent
   *                               should be used.
   * @param  wrapColumn            The column at which to wrap long lines.  A
   *                               value less than or equal to two indicates
   *                               that no wrapping should be performed.  If
   *                               both an indent and a wrap column are to be
   *                               used, then the wrap column must be greater
   *                               than the indent.
   * @param  endWithNewline        Indicates whether a newline sequence should
   *                               follow the last line that is printed.
   * @param  msg                   The message components that will be written
   *                               to the standard output stream.  They will be
   *                               concatenated together on the same line, and
   *                               that line will be followed by an end-of-line
   *                               sequence.
   */
  final synchronized void wrapStandardOut(final int firstLineIndent,
                                          final int subsequentLineIndent,
                                          final int wrapColumn,
                                          final boolean endWithNewline,
                                          @NotNull final Object... msg)
  {
    write(out, firstLineIndent, subsequentLineIndent, wrapColumn,
         endWithNewline, msg);
  }



  /**
   * Retrieves the print stream that will be used for standard error.
   *
   * @return  The print stream that will be used for standard error.
   */
  @NotNull()
  public final PrintStream getErr()
  {
    return err;
  }



  /**
   * Retrieves the print stream that may be used to write to the original
   * standard error.  This may be different from the current standard error
   * stream if an output file has been configured.
   *
   * @return  The print stream that may be used to write to the original
   *          standard error.
   */
  @NotNull()
  public final PrintStream getOriginalErr()
  {
    return originalErr;
  }



  /**
   * Writes the provided message to the standard error stream for this tool.
   * <BR><BR>
   * This method is completely threadsafe and my be invoked concurrently by any
   * number of threads.
   *
   * @param  msg  The message components that will be written to the standard
   *              error stream.  They will be concatenated together on the same
   *              line, and that line will be followed by an end-of-line
   *              sequence.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final synchronized void err(@NotNull final Object... msg)
  {
    write(err, 0, 0, msg);
  }



  /**
   * Writes the provided message to the standard error stream for this tool,
   * optionally wrapping and/or indenting the text in the process.
   * <BR><BR>
   * This method is completely threadsafe and my be invoked concurrently by any
   * number of threads.
   *
   * @param  indent      The number of spaces each line should be indented.  A
   *                     value less than or equal to zero indicates that no
   *                     indent should be used.
   * @param  wrapColumn  The column at which to wrap long lines.  A value less
   *                     than or equal to two indicates that no wrapping should
   *                     be performed.  If both an indent and a wrap column are
   *                     to be used, then the wrap column must be greater than
   *                     the indent.
   * @param  msg         The message components that will be written to the
   *                     standard output stream.  They will be concatenated
   *                     together on the same line, and that line will be
   *                     followed by an end-of-line sequence.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  public final synchronized void wrapErr(final int indent, final int wrapColumn,
                                         @NotNull final Object... msg)
  {
    write(err, indent, wrapColumn, msg);
  }



  /**
   * Writes the provided message to the given print stream, optionally wrapping
   * and/or indenting the text in the process.
   *
   * @param  stream      The stream to which the message should be written.
   * @param  indent      The number of spaces each line should be indented.  A
   *                     value less than or equal to zero indicates that no
   *                     indent should be used.
   * @param  wrapColumn  The column at which to wrap long lines.  A value less
   *                     than or equal to two indicates that no wrapping should
   *                     be performed.  If both an indent and a wrap column are
   *                     to be used, then the wrap column must be greater than
   *                     the indent.
   * @param  msg         The message components that will be written to the
   *                     standard output stream.  They will be concatenated
   *                     together on the same line, and that line will be
   *                     followed by an end-of-line sequence.
   */
  private static void write(@NotNull final PrintStream stream,
                            final int indent,
                            final int wrapColumn,
                            @NotNull final Object... msg)
  {
    write(stream, indent, indent, wrapColumn, true, msg);
  }



  /**
   * Writes the provided message to the given print stream, optionally wrapping
   * and/or indenting the text in the process.
   *
   * @param  stream                The stream to which the message should be
   *                               written.
   * @param  firstLineIndent       The number of spaces the first line should be
   *                               indented.  A value less than or equal to zero
   *                               indicates that no indent should be used.
   * @param  subsequentLineIndent  The number of spaces all lines after the
   *                               first should be indented.  A value less than
   *                               or equal to zero indicates that no indent
   *                               should be used.
   * @param  wrapColumn            The column at which to wrap long lines.  A
   *                               value less than or equal to two indicates
   *                               that no wrapping should be performed.  If
   *                               both an indent and a wrap column are to be
   *                               used, then the wrap column must be greater
   *                               than the indent.
   * @param  endWithNewline        Indicates whether a newline sequence should
   *                               follow the last line that is printed.
   * @param  msg                   The message components that will be written
   *                               to the standard output stream.  They will be
   *                               concatenated together on the same line, and
   *                               that line will be followed by an end-of-line
   *                               sequence.
   */
  private static void write(@NotNull final PrintStream stream,
                            final int firstLineIndent,
                            final int subsequentLineIndent,
                            final int wrapColumn,
                            final boolean endWithNewline,
                            @NotNull final Object... msg)
  {
    final StringBuilder buffer = new StringBuilder();
    for (final Object o : msg)
    {
      buffer.append(o);
    }

    if (wrapColumn > 2)
    {
      boolean firstLine = true;
      for (final String line :
           StaticUtils.wrapLine(buffer.toString(),
                (wrapColumn - firstLineIndent),
                (wrapColumn - subsequentLineIndent)))
      {
        final int indent;
        if (firstLine)
        {
          indent = firstLineIndent;
          firstLine = false;
        }
        else
        {
          stream.println();
          indent = subsequentLineIndent;
        }

        if (indent > 0)
        {
          for (int i=0; i < indent; i++)
          {
            stream.print(' ');
          }
        }
        stream.print(line);
      }
    }
    else
    {
      if (firstLineIndent > 0)
      {
        for (int i=0; i < firstLineIndent; i++)
        {
          stream.print(' ');
        }
      }
      stream.print(buffer.toString());
    }

    if (endWithNewline)
    {
      stream.println();
    }
    stream.flush();
  }
}
