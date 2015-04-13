/*
 * Copyright 2010-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2014 UnboundID Corp.
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
package com.unboundid.ldap.sdk.examples;



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;

import com.unboundid.ldap.listener.LDAPDebuggerRequestHandler;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.ProxyRequestHandler;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.MinimalLogFormatter;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a tool that can be used to create a simple listener that
 * may be used to intercept and decode LDAP requests before forwarding them to
 * another Directory Server, and then intercept and decode responses before
 * returning them to the client.  Some of the APIs demonstrated by this example
 * include:
 * <UL>
 *   <LI>Argument Parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 *   <LI>LDAP Command-Line Tool (from the {@code com.unboundid.util}
 *       package)</LI>
 *   <LI>LDAP Listener API (from the {@code com.unboundid.ldap.listener}
 *       package)</LI>
 * </UL>
 * <BR><BR>
 * All of the necessary information is provided using
 * command line arguments.  Supported arguments include those allowed by the
 * {@link LDAPCommandLineTool} class, as well as the following additional
 * arguments:
 * <UL>
 *   <LI>"-a {address}" or "--listenAddress {address}" -- Specifies the address
 *       on which to listen for requests from clients.</LI>
 *   <LI>"-L {port}" or "--listenPort {port}" -- Specifies the port on which to
 *       listen for requests from clients.</LI>
 *   <LI>"-S" or "--listenUsingSSL" -- Indicates that the listener should
 *       accept connections from SSL-based clients rather than those using
 *       unencrypted LDAP.</LI>
 *   <LI>"-f {path}" or "--outputFile {path}" -- Specifies the path to the
 *       output file to be written.  If this is not provided, then the output
 *       will be written to standard output.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPDebugger
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8942937427428190983L;



  // The argument used to specify the output file for the decoded content.
  private BooleanArgument listenUsingSSL;

  // The argument used to specify the output file for the decoded content.
  private FileArgument outputFile;

  // The argument used to specify the port on which to listen for client
  // connections.
  private IntegerArgument listenPort;

  // The shutdown hook that will be used to stop the listener when the JVM
  // exits.
  private LDAPDebuggerShutdownListener shutdownListener;

  // The listener used to intercept and decode the client communication.
  private LDAPListener listener;

  // The argument used to specify the address on which to listen for client
  // connections.
  private StringArgument listenAddress;



  /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String[] args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final LDAPDebugger ldapDebugger = new LDAPDebugger(outStream, errStream);
    return ldapDebugger.runTool(args);
  }



  /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
  public LDAPDebugger(final OutputStream outStream,
                      final OutputStream errStream)
  {
    super(outStream, errStream);
  }



  /**
   * Retrieves the name for this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  public String getToolName()
  {
    return "ldap-debugger";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Intercept and decode LDAP communication.";
  }



  /**
   * Retrieves the version string for this tool.
   *
   * @return  The version string for this tool.
   */
  @Override()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Adds the arguments used by this program that aren't already provided by the
   * generic {@code LDAPCommandLineTool} framework.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    String description = "The address on which to listen for client " +
         "connections.  If this is not provided, then it will listen on " +
         "all interfaces.";
    listenAddress = new StringArgument('a', "listenAddress", false, 1,
         "{address}", description);
    parser.addArgument(listenAddress);


    description = "The port on which to listen for client connections.  If " +
         "no value is provided, then a free port will be automatically " +
         "selected.";
    listenPort = new IntegerArgument('L', "listenPort", true, 1, "{port}",
         description, 0, 65535, 0);
    parser.addArgument(listenPort);


    description = "Use SSL when accepting client connections.  This is " +
         "independent of the '--useSSL' option, which applies only to " +
         "communication between the LDAP debugger and the backend server.";
    listenUsingSSL = new BooleanArgument('S', "listenUsingSSL", 1,
         description);
    parser.addArgument(listenUsingSSL);


    description = "The path to the output file to be written.  If no value " +
         "is provided, then the output will be written to standard output.";
    outputFile = new FileArgument('f', "outputFile", false, 1, "{path}",
         description, false, true, true, false);
    parser.addArgument(outputFile);
  }



  /**
   * Performs the actual processing for this tool.  In this case, it gets a
   * connection to the directory server and uses it to perform the requested
   * search.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Create the proxy request handler that will be used to forward requests to
    // a remote directory.
    final ProxyRequestHandler proxyHandler;
    try
    {
      proxyHandler = new ProxyRequestHandler(createServerSet());
    }
    catch (final LDAPException le)
    {
      err("Unable to prepare to connect to the target server:  ",
           le.getMessage());
      return le.getResultCode();
    }


    // Create the log handler to use for the output.
    final Handler logHandler;
    if (outputFile.isPresent())
    {
      try
      {
        logHandler = new FileHandler(outputFile.getValue().getAbsolutePath());
      }
      catch (final IOException ioe)
      {
        err("Unable to open the output file for writing:  ",
             StaticUtils.getExceptionMessage(ioe));
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      logHandler = new ConsoleHandler();
    }
    logHandler.setLevel(Level.INFO);
    logHandler.setFormatter(new MinimalLogFormatter(
         MinimalLogFormatter.DEFAULT_TIMESTAMP_FORMAT, false, false, true));


    // Create the debugger request handler that will be used to write the
    // debug output.
    final LDAPDebuggerRequestHandler debuggingHandler =
         new LDAPDebuggerRequestHandler(logHandler, proxyHandler);


    // Create and start the LDAP listener.
    final LDAPListenerConfig config =
         new LDAPListenerConfig(listenPort.getValue(), debuggingHandler);
    if (listenAddress.isPresent())
    {
      try
      {
        config.setListenAddress(
             InetAddress.getByName(listenAddress.getValue()));
      }
      catch (final Exception e)
      {
        err("Unable to resolve '", listenAddress.getValue(),
            "' as a valid address:  ", StaticUtils.getExceptionMessage(e));
        return ResultCode.PARAM_ERROR;
      }
    }

    if (listenUsingSSL.isPresent())
    {
      try
      {
        config.setServerSocketFactory(
             createSSLUtil(true).createSSLServerSocketFactory());
      }
      catch (final Exception e)
      {
        err("Unable to create a server socket factory to accept SSL-based " +
             "client connections:  ", StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }

    listener = new LDAPListener(config);

    try
    {
      listener.startListening();
    }
    catch (final Exception e)
    {
      err("Unable to start listening for client connections:  ",
          StaticUtils.getExceptionMessage(e));
      return ResultCode.LOCAL_ERROR;
    }


    // Display a message with information about the port on which it is
    // listening for connections.
    int port = listener.getListenPort();
    while (port <= 0)
    {
      try
      {
        Thread.sleep(1L);
      } catch (final Exception e) {}

      port = listener.getListenPort();
    }

    if (listenUsingSSL.isPresent())
    {
      out("Listening for SSL-based LDAP client connections on port ", port);
    }
    else
    {
      out("Listening for LDAP client connections on port ", port);
    }

    // Note that at this point, the listener will continue running in a
    // separate thread, so we can return from this thread without exiting the
    // program.  However, we'll want to register a shutdown hook so that we can
    // close the logger.
    shutdownListener = new LDAPDebuggerShutdownListener(listener, logHandler);
    Runtime.getRuntime().addShutdownHook(shutdownListener);

    return ResultCode.SUCCESS;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>();

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--listenPort", "1389",
      "--outputFile", "/tmp/ldap-debugger.log"
    };
    final String description =
         "Listen for client connections on port 1389 on all interfaces and " +
         "forward any traffic received to server.example.com:389.  The " +
         "decoded LDAP communication will be written to the " +
         "/tmp/ldap-debugger.log log file.";
    examples.put(args, description);

    return examples;
  }



  /**
   * Retrieves the LDAP listener used to decode the communication.
   *
   * @return  The LDAP listener used to decode the communication, or
   *          {@code null} if the tool is not running.
   */
  public LDAPListener getListener()
  {
    return listener;
  }



  /**
   * Indicates that the associated listener should shut down.
   */
  public void shutDown()
  {
    Runtime.getRuntime().removeShutdownHook(shutdownListener);
    shutdownListener.run();
  }
}
