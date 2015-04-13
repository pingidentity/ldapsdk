/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
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
 *     |
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
  // The print stream to use for messages written to standard output.
  private final PrintStream out;

  // The print stream to use for messages written to standard error.
  private final PrintStream err;

  // The argument used to request tool help.
  private BooleanArgument helpArgument = null;

  // The argument used to request the tool version.
  private BooleanArgument versionArgument = null;



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
  public CommandLineTool(final OutputStream outStream,
                         final OutputStream errStream)
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
  public final ResultCode runTool(final String... args)
  {
    try
    {
      final ArgumentParser parser = createArgumentParser();
      parser.parse(args);

      if (helpArgument.isPresent())
      {
        out(parser.getUsageString(79));
        displayExampleUsages();
        return ResultCode.SUCCESS;
      }

      if ((versionArgument != null) && versionArgument.isPresent())
      {
        out(getToolVersion());
        return ResultCode.SUCCESS;
      }

      doExtendedArgumentValidation();
    }
    catch (ArgumentException ae)
    {
      debugException(ae);
      err(ae.getMessage());
      return ResultCode.PARAM_ERROR;
    }


    final AtomicReference<ResultCode> exitCode =
         new AtomicReference<ResultCode>();
    if (registerShutdownHook())
    {
      final CommandLineToolShutdownHook shutdownHook =
           new CommandLineToolShutdownHook(this, exitCode);
      Runtime.getRuntime().addShutdownHook(shutdownHook);
    }

    try
    {
      exitCode.set(doToolProcessing());
    }
    catch (Exception e)
    {
      debugException(e);
      err(getExceptionMessage(e));
      exitCode.set(ResultCode.LOCAL_ERROR);
    }

    return exitCode.get();
  }



  /**
   * Writes example usage information for this tool to the standard output
   * stream.
   */
  private void displayExampleUsages()
  {
    final LinkedHashMap<String[],String> examples = getExampleUsages();
    if ((examples == null) || examples.isEmpty())
    {
      return;
    }

    out(INFO_CL_TOOL_LABEL_EXAMPLES);

    for (final Map.Entry<String[],String> e : examples.entrySet())
    {
      out();
      wrapOut(2, 79, e.getValue());
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
            ExampleCommandLineArgument cleanArg =
                ExampleCommandLineArgument.getCleanArgument(args[i+1]);
            arg += ' ' + cleanArg.getLocalForm();
            i++;
          }
        }
        else
        {
          ExampleCommandLineArgument cleanArg =
              ExampleCommandLineArgument.getCleanArgument(arg);
          arg = cleanArg.getLocalForm();
        }

        if ((buffer.length() + arg.length() + 2) < 79)
        {
          buffer.append(arg);
        }
        else
        {
          buffer.append('\\');
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
  public abstract String getToolName();



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  public abstract String getToolDescription();



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  public String getToolVersion()
  {
    return null;
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
  public String getTrailingArgumentsPlaceholder()
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
  public final ArgumentParser createArgumentParser()
         throws ArgumentException
  {
    final ArgumentParser parser = new ArgumentParser(getToolName(),
         getToolDescription(), getMaxTrailingArguments(),
         getTrailingArgumentsPlaceholder());

    addToolArguments(parser);

    helpArgument = new BooleanArgument('H', "help",
         INFO_CL_TOOL_DESCRIPTION_HELP.get());
    helpArgument.addShortIdentifier('?');
    helpArgument.setUsageArgument(true);
    parser.addArgument(helpArgument);

    final String version = getToolVersion();
    if ((version != null) && (version.length() > 0) &&
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

    return parser;
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
  public abstract void addToolArguments(final ArgumentParser parser)
         throws ArgumentException;



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and immediately
   * before the {@link CommandLineTool#doToolProcessing} method is invoked.
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
  protected void doShutdownHookProcessing(final ResultCode resultCode)
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
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    return null;
  }



  /**
   * Retrieves the print writer that will be used for standard output.
   *
   * @return  The print writer that will be used for standard output.
   */
  public final PrintStream getOut()
  {
    return out;
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
  public final synchronized void out(final Object... msg)
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
                                         final Object... msg)
  {
    write(out, indent, wrapColumn, msg);
  }



  /**
   * Retrieves the print writer that will be used for standard error.
   *
   * @return  The print writer that will be used for standard error.
   */
  public final PrintStream getErr()
  {
    return err;
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
  public final synchronized void err(final Object... msg)
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
                                         final Object... msg)
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
  private static void write(final PrintStream stream, final int indent,
                            final int wrapColumn, final Object... msg)
  {
    final StringBuilder buffer = new StringBuilder();
    for (final Object o : msg)
    {
      buffer.append(o);
    }

    if (wrapColumn > 2)
    {
      final List<String> lines;
      if (indent > 0)
      {
        for (final String line :
             wrapLine(buffer.toString(), (wrapColumn - indent)))
        {
          for (int i=0; i < indent; i++)
          {
            stream.print(' ');
          }
          stream.println(line);
        }
      }
      else
      {
        for (final String line : wrapLine(buffer.toString(), wrapColumn))
        {
          stream.println(line);
        }
      }
    }
    else
    {
      if (indent > 0)
      {
        for (int i=0; i < indent; i++)
        {
          stream.print(' ');
        }
      }
      stream.println(buffer.toString());
    }
  }
}
