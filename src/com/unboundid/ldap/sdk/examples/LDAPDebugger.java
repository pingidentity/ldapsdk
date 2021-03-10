/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;

import com.unboundid.ldap.listener.LDAPDebuggerRequestHandler;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.ProxyRequestHandler;
import com.unboundid.ldap.listener.SelfSignedCertificateGenerator;
import com.unboundid.ldap.listener.ToCodeRequestHandler;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.MinimalLogFormatter;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a tool that can be used to create a simple listener that
 * may be used to intercept and decode LDAP requests before forwarding them to
 * another directory server, and then intercept and decode responses before
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
 *   <LI>"-c {path}" or "--codeLogFile {path}" -- Specifies the path to a file
 *       to be written with generated code that corresponds to requests received
 *       from clients.  If this is not provided, then no code log will be
 *       generated.</LI>
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



  // The argument parser for this tool.
  @Nullable private ArgumentParser parser;

  // The argument used to specify the output file for the decoded content.
  @Nullable private BooleanArgument listenUsingSSL;

  // The argument used to indicate that the listener should generate a
  // self-signed certificate instead of using an existing keystore.
  @Nullable private BooleanArgument generateSelfSignedCertificate;

  // The argument used to specify the code log file to use, if any.
  @Nullable private FileArgument codeLogFile;

  // The argument used to specify the output file for the decoded content.
  @Nullable private FileArgument outputFile;

  // The argument used to specify the port on which to listen for client
  // connections.
  @Nullable private IntegerArgument listenPort;

  // The shutdown hook that will be used to stop the listener when the JVM
  // exits.
  @Nullable private LDAPDebuggerShutdownListener shutdownListener;

  // The listener used to intercept and decode the client communication.
  @Nullable private LDAPListener listener;

  // The argument used to specify the address on which to listen for client
  // connections.
  @Nullable private StringArgument listenAddress;



  /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String[] args)
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
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream)
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
  public LDAPDebugger(@Nullable final OutputStream outStream,
                      @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);
  }



  /**
   * Retrieves the name for this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
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
  @NotNull()
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
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
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
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
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
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool should default to interactively prompting for
   * the bind password if a password is required but no argument was provided
   * to indicate how to get the password.
   *
   * @return  {@code true} if this tool should default to interactively
   *          prompting for the bind password, or {@code false} if not.
   */
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
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
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Indicates whether the LDAP-specific arguments should include alternate
   * versions of all long identifiers that consist of multiple words so that
   * they are available in both camelCase and dash-separated versions.
   *
   * @return  {@code true} if this tool should provide multiple versions of
   *          long identifiers for LDAP-specific arguments, or {@code false} if
   *          not.
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide a command-line argument that
   * allows for low-level SSL debugging.  If this returns {@code true}, then an
   * "--enableSSLDebugging}" argument will be added that sets the
   * "javax.net.debug" system property to "all" before attempting any
   * communication.
   *
   * @return  {@code true} if this tool should offer an "--enableSSLDebugging"
   *          argument, or {@code false} if not.
   */
  @Override()
  protected boolean supportsSSLDebugging()
  {
    return true;
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
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;

    String description = "The address on which to listen for client " +
         "connections.  If this is not provided, then it will listen on " +
         "all interfaces.";
    listenAddress = new StringArgument('a', "listenAddress", false, 1,
         "{address}", description);
    listenAddress.addLongIdentifier("listen-address", true);
    parser.addArgument(listenAddress);


    description = "The port on which to listen for client connections.  If " +
         "no value is provided, then a free port will be automatically " +
         "selected.";
    listenPort = new IntegerArgument('L', "listenPort", true, 1, "{port}",
         description, 0, 65_535, 0);
    listenPort.addLongIdentifier("listen-port", true);
    parser.addArgument(listenPort);


    description = "Use SSL when accepting client connections.  This is " +
         "independent of the '--useSSL' option, which applies only to " +
         "communication between the LDAP debugger and the backend server.  " +
         "If this argument is provided, then either the --keyStorePath or " +
         "the --generateSelfSignedCertificate argument must also be provided.";
    listenUsingSSL = new BooleanArgument('S', "listenUsingSSL", 1,
         description);
    listenUsingSSL.addLongIdentifier("listen-using-ssl", true);
    parser.addArgument(listenUsingSSL);


    description = "Generate a self-signed certificate to present to clients " +
         "when the --listenUsingSSL argument is provided.  This argument " +
         "cannot be used in conjunction with the --keyStorePath argument.";
    generateSelfSignedCertificate = new BooleanArgument(null,
         "generateSelfSignedCertificate", 1, description);
    generateSelfSignedCertificate.addLongIdentifier(
         "generate-self-signed-certificate", true);
    parser.addArgument(generateSelfSignedCertificate);


    description = "The path to the output file to be written.  If no value " +
         "is provided, then the output will be written to standard output.";
    outputFile = new FileArgument('f', "outputFile", false, 1, "{path}",
         description, false, true, true, false);
    outputFile.addLongIdentifier("output-file", true);
    parser.addArgument(outputFile);


    description = "The path to the a code log file to be written.  If a " +
         "value is provided, then the tool will generate sample code that " +
         "corresponds to the requests received from clients.  If no value is " +
         "provided, then no code log will be generated.";
    codeLogFile = new FileArgument('c', "codeLogFile", false, 1, "{path}",
         description, false, true, true, false);
    codeLogFile.addLongIdentifier("code-log-file", true);
    parser.addArgument(codeLogFile);


    // If --listenUsingSSL is provided, then either the --keyStorePath argument
    // or the --generateSelfSignedCertificate argument must also be provided.
    final Argument keyStorePathArgument =
         parser.getNamedArgument("keyStorePath");
    parser.addDependentArgumentSet(listenUsingSSL, keyStorePathArgument,
         generateSelfSignedCertificate);


    // The --generateSelfSignedCertificate argument cannot be used with any of
    // the arguments pertaining to a key store path.
    final Argument keyStorePasswordArgument =
         parser.getNamedArgument("keyStorePassword");
    final Argument keyStorePasswordFileArgument =
         parser.getNamedArgument("keyStorePasswordFile");
    final Argument promptForKeyStorePasswordArgument =
         parser.getNamedArgument("promptForKeyStorePassword");
    parser.addExclusiveArgumentSet(generateSelfSignedCertificate,
         keyStorePathArgument);
    parser.addExclusiveArgumentSet(generateSelfSignedCertificate,
         keyStorePasswordArgument);
    parser.addExclusiveArgumentSet(generateSelfSignedCertificate,
         keyStorePasswordFileArgument);
    parser.addExclusiveArgumentSet(generateSelfSignedCertificate,
         promptForKeyStorePasswordArgument);
  }



  /**
   * Performs the actual processing for this tool.  In this case, it gets a
   * connection to the directory server and uses it to perform the requested
   * search.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  @NotNull()
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
    StaticUtils.setLogHandlerLevel(logHandler, Level.INFO);
    logHandler.setFormatter(new MinimalLogFormatter(
         MinimalLogFormatter.DEFAULT_TIMESTAMP_FORMAT, false, false, true));


    // Create the debugger request handler that will be used to write the
    // debug output.
    LDAPListenerRequestHandler requestHandler =
         new LDAPDebuggerRequestHandler(logHandler, proxyHandler);


    // If a code log file was specified, then create the appropriate request
    // handler to accomplish that.
    if (codeLogFile.isPresent())
    {
      try
      {
        requestHandler = new ToCodeRequestHandler(codeLogFile.getValue(), true,
             requestHandler);
      }
      catch (final Exception e)
      {
        err("Unable to open code log file '",
             codeLogFile.getValue().getAbsolutePath(), "' for writing:  ",
             StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Create and start the LDAP listener.
    final LDAPListenerConfig config =
         new LDAPListenerConfig(listenPort.getValue(), requestHandler);
    if (listenAddress.isPresent())
    {
      try
      {
        config.setListenAddress(LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
             getByName(listenAddress.getValue()));
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
        final SSLUtil sslUtil;
        if (generateSelfSignedCertificate.isPresent())
        {
          final ObjectPair<File,char[]> keyStoreInfo =
               SelfSignedCertificateGenerator.
                    generateTemporarySelfSignedCertificate(getToolName(),
                         CryptoHelper.KEY_STORE_TYPE_JKS);

          sslUtil = new SSLUtil(
               new KeyStoreKeyManager(keyStoreInfo.getFirst(),
                    keyStoreInfo.getSecond(), CryptoHelper.KEY_STORE_TYPE_JKS,
                    null, true),
               new TrustAllTrustManager(false));
        }
        else
        {
          sslUtil = createSSLUtil(true);
        }

        config.setServerSocketFactory(sslUtil.createSSLServerSocketFactory());
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
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
        }
      }

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
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

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
  @Nullable()
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
