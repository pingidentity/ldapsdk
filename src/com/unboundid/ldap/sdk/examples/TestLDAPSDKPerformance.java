/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ServerSocketFactory;

import com.unboundid.ldap.listener.CannedResponseRequestHandler;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.cert.ManageCertificates;



/**
 * This class implements a command-line tool that can be helpful in measuring
 * the performance of the LDAP SDK itself.  It creates an {@link LDAPListener}
 * that uses a {@link CannedResponseRequestHandler} to return a predefined
 * response to any request that it receives.  It will then use one of the
 * {@link SearchRate}, {@link ModRate}, {@link AuthRate}, or
 * {@link SearchAndModRate} tools to issue concurrent operations against that
 * listener instance as quickly as possible.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TestLDAPSDKPerformance
       extends CommandLineTool
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN =
       StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The name for the authrate tool.
   */
  @NotNull private static final String TOOL_NAME_AUTHRATE = "authrate";



  /**
   * The name for the modrate tool.
   */
  @NotNull private static final String TOOL_NAME_MODRATE = "modrate";



  /**
   * The name for the search-and-mod-rate tool.
   */
  @NotNull private static final String TOOL_NAME_SEARCH_AND_MOD_RATE =
       "search-and-mod-rate";



  /**
   * The name for the searchrate tool.
   */
  @NotNull private static final String TOOL_NAME_SEARCHRATE = "searchrate";



  // A reference to the completion message for the tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // The argument used to indicate that the authrate tool should only perform
  // binds rather than both binds and searches.
  @Nullable private BooleanArgument bindOnlyArg;

  // The argument used to indicate whether to communicate with the listener
  // over an SSL-encrypted connection.
  @Nullable private BooleanArgument useSSLArg;

  // The argument used to specify the number of entries to return in response to
  // each search.
  @Nullable private IntegerArgument entriesPerSearchArg;

  // The argument used to specify the duration (in seconds) to use for each
  // interval.
  @Nullable private IntegerArgument intervalDurationSecondsArg;

  // The argument used to specify the number of intervals to complete.
  @Nullable private IntegerArgument numIntervalsArg;

  // The argument used to specify the number of concurrent threads to use when
  // searching.
  @Nullable private IntegerArgument numThreadsArg;

  // The argument used to specify the result code to return in response to each
  // operation.
  @Nullable private IntegerArgument resultCodeArg;

  // The argument used to specify the number of warm-up intervals to use whose
  // performance will be ignored in the final results.
  @Nullable private IntegerArgument warmUpIntervalsArg;

  // The argument used to specify the diagnostic message to include in each
  // search result done message.
  @Nullable private StringArgument diagnosticMessageArg;

  // The argument used to specify the name of the tool to invoke for the
  // performance testing.
  @Nullable private StringArgument toolArg;



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Runs this tool with the provided set of command-line arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  A result code indicating the result of tool processing.  Any
   *          result code other than {@link ResultCode#SUCCESS} should be
   *          considered an error.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final TestLDAPSDKPerformance tool = new TestLDAPSDKPerformance(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this command-line tool.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public TestLDAPSDKPerformance(@Nullable final OutputStream out,
                                @Nullable final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();

    bindOnlyArg = null;
    useSSLArg = null;
    entriesPerSearchArg = null;
    intervalDurationSecondsArg = null;
    numIntervalsArg = null;
    numThreadsArg = null;
    resultCodeArg = null;
    warmUpIntervalsArg = null;
    diagnosticMessageArg = null;
    toolArg = null;
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "test-ldap-sdk-performance";
  }



  /**
   * Retrieves a human-readable description for this tool.  If the description
   * should include multiple paragraphs, then this method should return the text
   * for the first paragraph, and the
   * {@link #getAdditionalDescriptionParagraphs()} method should be used to
   * return the text for the subsequent paragraphs.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "Provides a mechanism to help test the performance of the LDAP SDK.";
  }



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
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.singletonList(
         "It creates an LDAP listener that uses a canned-response request " +
              "handler to return a predefined response to all requests.  It" +
              "then invokes another tool (either searchrate, modrate, " +
              "authrate, or search-and-mod-rate) to issue concurrent " +
              "requests against that listener as quickly as possible.");
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
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
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
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
  @Override()
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return completionMessage.get();
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
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    toolArg = new StringArgument(null, "tool", true, 1,
         "{searchrate|modrate|authrate|search-and-mod-rate}",
         "The tool to invoke against the LDAP listener.  It may be one of " +
              "searchrate, modrate, authrate, or search-and-mod-rate.  If " +
              "this is not provided, then the searchrate tool will be invoked.",
         StaticUtils.setOf(TOOL_NAME_SEARCHRATE,
              TOOL_NAME_MODRATE,
              TOOL_NAME_AUTHRATE,
              TOOL_NAME_SEARCH_AND_MOD_RATE),
         TOOL_NAME_SEARCHRATE);
    toolArg.addLongIdentifier("toolName", true);
    toolArg.addLongIdentifier("tool-name", true);
    parser.addArgument(toolArg);


    numThreadsArg = new IntegerArgument('t', "numThreads", true, 1, "{num}",
         "The number of concurrent threads (each using its own connection) " +
              "to use to process requests.  If this is not provided, then a " +
              "single thread will be used.",
         1, Integer.MAX_VALUE, 1);
    numThreadsArg.addLongIdentifier("num-threads", true);
    numThreadsArg.addLongIdentifier("threads", true);
    parser.addArgument(numThreadsArg);


    entriesPerSearchArg = new IntegerArgument(null, "entriesPerSearch", true,
         1, "{num}",
         "The number of entries to return in response to each search " +
              "request.  If this is provided, the value must be between 0 " +
              "and 100.  If it is not provided, then a single entry will be " +
              "returned.",
         0, 100, 1);
    entriesPerSearchArg.addLongIdentifier("entries-per-search", true);
    entriesPerSearchArg.addLongIdentifier("numEntries", true);
    entriesPerSearchArg.addLongIdentifier("num-entries", true);
    entriesPerSearchArg.addLongIdentifier("entries", true);
    parser.addArgument(entriesPerSearchArg);


    bindOnlyArg = new BooleanArgument(null, "bindOnly", 1,
         "Indicates that the authrate tool should only issue bind requests.  " +
              "If this is not provided, the authrate tool will perform both " +
              "search and bind operations.  This argument will only be used " +
              "in conjunction with the authrate tool.");
    bindOnlyArg.addLongIdentifier("bind-only", true);
    parser.addArgument(bindOnlyArg);


    resultCodeArg = new IntegerArgument(null, "resultCode", true, 1,
         "{intValue}",
         "The integer value for the result code to return in response to " +
              "each request.  If this is not provided, then a result code of " +
              "0 (success) will be returned.",
         0, Integer.MAX_VALUE, ResultCode.SUCCESS_INT_VALUE);
    resultCodeArg.addLongIdentifier("result-code", true);
    parser.addArgument(resultCodeArg);


    diagnosticMessageArg = new StringArgument(null, "diagnosticMessage", false,
         1, "{message}",
         "The diagnostic message to return in response to each request.  If " +
              "this is not provided, then no diagnostic message will be " +
              "returned.");
    diagnosticMessageArg.addLongIdentifier("diagnostic-message", true);
    diagnosticMessageArg.addLongIdentifier("errorMessage", true);
    diagnosticMessageArg.addLongIdentifier("error-message", true);
    diagnosticMessageArg.addLongIdentifier("message", true);
    parser.addArgument(diagnosticMessageArg);


    useSSLArg = new BooleanArgument('Z', "useSSL", 1,
         "Encrypt communication with SSL.  If this argument is not provided, " +
              "then the communication will not be encrypted.");
    useSSLArg.addLongIdentifier("use-ssl", true);
    useSSLArg.addLongIdentifier("ssl", true);
    useSSLArg.addLongIdentifier("useTLS", true);
    useSSLArg.addLongIdentifier("use-tls", true);
    useSSLArg.addLongIdentifier("tls", true);
    parser.addArgument(useSSLArg);


    numIntervalsArg = new IntegerArgument('I', "numIntervals", false, 1,
         "{num}",
         "The number of intervals to use when running the performance " +
              "measurement tool.  If this argument is provided in " +
              "conjunction with the --warmUpIntervals argument, then the " +
              "warm-up intervals will not be included in this count, and the " +
              "total number of intervals run will be the sum of the two " +
              "values.  If this argument is not provided, then the tool will " +
              "run until it is interrupted (e.g., by pressing Ctrl+C or by " +
              "killing the underlying Java process).",
         0, Integer.MAX_VALUE);
    numIntervalsArg.addLongIdentifier("num-intervals", true);
    numIntervalsArg.addLongIdentifier("intervals", true);
    parser.addArgument(numIntervalsArg);


    intervalDurationSecondsArg = new IntegerArgument('i',
         "intervalDurationSeconds", true, 1, "{num}",
         "The length of time in seconds to use for each tool interval (that " +
              "is, the length of time between each line of output giving " +
              "statistical information for operations processed in that " +
              "interval).  If this is not provided, then a default interval " +
              "duration of five seconds will be used.",
         1, Integer.MAX_VALUE, 5);
    intervalDurationSecondsArg.addLongIdentifier("interval-duration-seconds",
         true);
    intervalDurationSecondsArg.addLongIdentifier("intervalDuration", true);
    intervalDurationSecondsArg.addLongIdentifier("interval-duration", true);
    parser.addArgument(intervalDurationSecondsArg);


    warmUpIntervalsArg = new IntegerArgument(null, "warmUpIntervals", true, 1,
         "{num}",
         "The number of intervals to run before starting to actually " +
              "collect statistics to include in the final result.  This can " +
              "give the JVM and JIT a chance to identify and optimize " +
              "hotspots in the code for the best and most stable " +
              "performance.  If this is not provided, then no warm-up " +
              "intervals will be used and the tool will start collecting " +
              "statistics right away.",
         0, Integer.MAX_VALUE, 0);
    warmUpIntervalsArg.addLongIdentifier("warm-up-intervals", true);
    warmUpIntervalsArg.addLongIdentifier("warmup-intervals", true);
    warmUpIntervalsArg.addLongIdentifier("warmUp", true);
    warmUpIntervalsArg.addLongIdentifier("warm-up", true);
    parser.addArgument(warmUpIntervalsArg);
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Create the socket factory to use for accepting connections.  If the
    // --useSSL argument was provided, then create a temporary keystore and
    // generate a certificate in it.
    final ServerSocketFactory serverSocketFactory;
    if (useSSLArg.isPresent())
    {
      try
      {
        final File keyStoreFile = File.createTempFile(
             "test-ldap-sdk-performance-keystore-", ".jks");
        keyStoreFile.deleteOnExit();
        keyStoreFile.delete();

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ResultCode manageCertificatesResultCode =
             ManageCertificates.main(null, out, out,
                  "generate-self-signed-certificate",
                  "--keystore", keyStoreFile.getAbsolutePath(),
                  "--keystore-password", keyStoreFile.getAbsolutePath(),
                  "--keystore-type", CryptoHelper.KEY_STORE_TYPE_JKS,
                  "--alias", "server-cert",
                  "--subject-dn", "CN=Test LDAP SDK Performance");
        if (manageCertificatesResultCode != ResultCode.SUCCESS)
        {
          final String message = "ERROR:  Unable to use the " +
               "manage-certificates tool to generate a self-signed server " +
               "certificate to use for SSL communication.";
          completionMessage.compareAndSet(null, message);
          wrapErr(0, WRAP_COLUMN, message);
          err();
          wrapErr(0, WRAP_COLUMN, "The manage-certificates output was:");
          err();
          err(StaticUtils.toUTF8String(out.toByteArray()));
          return manageCertificatesResultCode;
        }

        final SSLUtil sslUtil = new SSLUtil(
             new KeyStoreKeyManager(keyStoreFile,
                  keyStoreFile.getAbsolutePath().toCharArray(),
                  CryptoHelper.KEY_STORE_TYPE_JKS, "server-cert"),
             new TrustAllTrustManager());
        serverSocketFactory = sslUtil.createSSLServerSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        final String message = "ERROR:  Unable to initialize support for SSL " +
             "communication:  " + StaticUtils.getExceptionMessage(e);
        completionMessage.compareAndSet(null, message);
        wrapErr(0, WRAP_COLUMN, message);
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      serverSocketFactory = ServerSocketFactory.getDefault();
    }


    // Create the search result entries to return in response to each search.
    final int numEntries = entriesPerSearchArg.getValue();
    final List<Entry> entries = new ArrayList<>(numEntries);
    for (int i=1; i <= numEntries; i++)
    {
      entries.add(new Entry(
           "uid=user." + i + ",ou=People,dc=example,dc=com",
           new Attribute("objectClass", "top", "person", "organizationalPerson",
                "inetOrgPerson"),
           new Attribute("uid", "user." + i),
           new Attribute("givenName", "User"),
           new Attribute("sn", String.valueOf(i)),
           new Attribute("cn", "User " + i),
           new Attribute("mail", "user." + i + "@example.com"),
           new Attribute("userPassword", "password")));
    }


    // Create a canned response request handler to use to return the responses.
    final CannedResponseRequestHandler cannedResponseRequestHandler =
         new CannedResponseRequestHandler(
              ResultCode.valueOf(resultCodeArg.getValue()),
              null, // Matched DN
              diagnosticMessageArg.getValue(),
              Collections.<String>emptyList(), // Referral URLs
              entries,
              Collections.<SearchResultReference>emptyList());


    // Create the LDAP listener to handle the requests.
    final LDAPListenerConfig listenerConfig =
         new LDAPListenerConfig(0, cannedResponseRequestHandler);
    listenerConfig.setServerSocketFactory(serverSocketFactory);

    final LDAPListener ldapListener = new LDAPListener(listenerConfig);
    try
    {
      ldapListener.startListening();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String message = "ERROR:  Unable to start listening for client " +
           "connections:  " + StaticUtils.getExceptionMessage(e);
      completionMessage.compareAndSet(null, message);
      wrapErr(0, WRAP_COLUMN, message);
      return ResultCode.LOCAL_ERROR;
    }

    try
    {
      final int listenPort = ldapListener.getListenPort();
      final String toolName = StaticUtils.toLowerCase(toolArg.getValue());
      switch (toolName)
      {
        case TOOL_NAME_SEARCHRATE:
          return invokeSearchRate(listenPort);
        case TOOL_NAME_MODRATE:
          return invokeModRate(listenPort);
        case TOOL_NAME_AUTHRATE:
          return invokeAuthRate(listenPort);
        case TOOL_NAME_SEARCH_AND_MOD_RATE:
          return invokeSearchAndModRate(listenPort);
        default:
          // This should never happen.
          final String message = "ERROR:  Unrecognized tool name:  " + toolName;
          completionMessage.compareAndSet(null, message);
          wrapErr(0, WRAP_COLUMN, message);
          return ResultCode.PARAM_ERROR;
      }
    }
    finally
    {
      ldapListener.shutDown(true);
    }
  }



  /**
   * Invokes the {@link SearchRate} tool with an appropriate set of arguments.
   *
   * @param  listenPort  The port on which the LDAP listener is listening.
   *
   * @return  The result code obtained from the {@code SearchRate} tool.
   */
  @NotNull()
  private ResultCode invokeSearchRate(final int listenPort)
  {
    final List<String> searchRateArgs = new ArrayList<>();

    searchRateArgs.add("--hostname");
    searchRateArgs.add("localhost");

    searchRateArgs.add("--port");
    searchRateArgs.add(String.valueOf(listenPort));

    if (useSSLArg.isPresent())
    {
      searchRateArgs.add("--useSSL");
      searchRateArgs.add("--trustAll");
    }

    searchRateArgs.add("--baseDN");
    searchRateArgs.add("dc=example,dc=com");

    searchRateArgs.add("--scope");
    searchRateArgs.add("sub");

    searchRateArgs.add("--filter");
    searchRateArgs.add("(objectClass=*)");

    searchRateArgs.add("--numThreads");
    searchRateArgs.add(String.valueOf(numThreadsArg.getValue()));

    if (numIntervalsArg.isPresent())
    {
      searchRateArgs.add("--numIntervals");
      searchRateArgs.add(String.valueOf(numIntervalsArg.getValue()));
    }

    if (intervalDurationSecondsArg.isPresent())
    {
      searchRateArgs.add("--intervalDuration");
      searchRateArgs.add(String.valueOf(
           intervalDurationSecondsArg.getValue()));
    }

    if (warmUpIntervalsArg.isPresent())
    {
      searchRateArgs.add("--warmUpIntervals");
      searchRateArgs.add(String.valueOf(warmUpIntervalsArg.getValue()));
    }

    final String[] searchRateArgsArray =
         searchRateArgs.toArray(StaticUtils.NO_STRINGS);

    final SearchRate searchRate = new SearchRate(getOut(), getErr());

    final ResultCode searchRateResultCode =
         searchRate.runTool(searchRateArgsArray);
    if (searchRateResultCode == ResultCode.SUCCESS)
    {
      final String message = "The searchrate tool completed successfully.";
      completionMessage.compareAndSet(null, message);
      wrapOut(0, WRAP_COLUMN, message);
    }
    else
    {
      final String message =
           "ERROR:  The searchrate tool exited with error result code " +
                searchRateResultCode + '.';
      completionMessage.compareAndSet(null, message);
      wrapErr(0, WRAP_COLUMN, message);
    }

    return searchRateResultCode;
  }



  /**
   * Invokes the {@link ModRate} tool with an appropriate set of arguments.
   *
   * @param  listenPort  The port on which the LDAP listener is listening.
   *
   * @return  The result code obtained from the {@code ModRate} tool.
   */
  @NotNull()
  private ResultCode invokeModRate(final int listenPort)
  {
    final List<String> modRateArgs = new ArrayList<>();

    modRateArgs.add("--hostname");
    modRateArgs.add("localhost");

    modRateArgs.add("--port");
    modRateArgs.add(String.valueOf(listenPort));

    if (useSSLArg.isPresent())
    {
      modRateArgs.add("--useSSL");
      modRateArgs.add("--trustAll");
    }

    modRateArgs.add("--entryDN");
    modRateArgs.add("dc=example,dc=com");

    modRateArgs.add("--attribute");
    modRateArgs.add("description");

    modRateArgs.add("--valuePattern");
    modRateArgs.add("value");

    modRateArgs.add("--numThreads");
    modRateArgs.add(String.valueOf(numThreadsArg.getValue()));

    if (numIntervalsArg.isPresent())
    {
      modRateArgs.add("--numIntervals");
      modRateArgs.add(String.valueOf(numIntervalsArg.getValue()));
    }

    if (intervalDurationSecondsArg.isPresent())
    {
      modRateArgs.add("--intervalDuration");
      modRateArgs.add(String.valueOf(
           intervalDurationSecondsArg.getValue()));
    }

    if (warmUpIntervalsArg.isPresent())
    {
      modRateArgs.add("--warmUpIntervals");
      modRateArgs.add(String.valueOf(warmUpIntervalsArg.getValue()));
    }

    final String[] modRateArgsArray =
         modRateArgs.toArray(StaticUtils.NO_STRINGS);

    final ModRate modRate = new ModRate(getOut(), getErr());

    final ResultCode modRateResultCode =
         modRate.runTool(modRateArgsArray);
    if (modRateResultCode == ResultCode.SUCCESS)
    {
      final String message = "The modrate tool completed successfully.";
      completionMessage.compareAndSet(null, message);
      wrapOut(0, WRAP_COLUMN, message);
    }
    else
    {
      final String message =
           "ERROR:  The modrate tool exited with error result code " +
                modRateResultCode + '.';
      completionMessage.compareAndSet(null, message);
      wrapErr(0, WRAP_COLUMN, message);
    }

    return modRateResultCode;
  }



  /**
   * Invokes the {@link AuthRate} tool with an appropriate set of arguments.
   *
   * @param  listenPort  The port on which the LDAP listener is listening.
   *
   * @return  The result code obtained from the {@code AuthRate} tool.
   */
  @NotNull()
  private ResultCode invokeAuthRate(final int listenPort)
  {
    final List<String> authRateArgs = new ArrayList<>();

    authRateArgs.add("--hostname");
    authRateArgs.add("localhost");

    authRateArgs.add("--port");
    authRateArgs.add(String.valueOf(listenPort));

    if (useSSLArg.isPresent())
    {
      authRateArgs.add("--useSSL");
      authRateArgs.add("--trustAll");
    }

    if (bindOnlyArg.isPresent())
    {
      authRateArgs.add("--bindOnly");

      authRateArgs.add("--baseDN");
      authRateArgs.add("uid=user.1,ou=People,dc=example,dc=com");
    }
    else
    {
      authRateArgs.add("--baseDN");
      authRateArgs.add("dc=example,dc=com");

      authRateArgs.add("--scope");
      authRateArgs.add("sub");

      authRateArgs.add("--filter");
      authRateArgs.add("(uid=user.1)");
    }

    authRateArgs.add("--credentials");
    authRateArgs.add("password");

    authRateArgs.add("--numThreads");
    authRateArgs.add(String.valueOf(numThreadsArg.getValue()));

    if (numIntervalsArg.isPresent())
    {
      authRateArgs.add("--numIntervals");
      authRateArgs.add(String.valueOf(numIntervalsArg.getValue()));
    }

    if (intervalDurationSecondsArg.isPresent())
    {
      authRateArgs.add("--intervalDuration");
      authRateArgs.add(String.valueOf(
           intervalDurationSecondsArg.getValue()));
    }

    if (warmUpIntervalsArg.isPresent())
    {
      authRateArgs.add("--warmUpIntervals");
      authRateArgs.add(String.valueOf(warmUpIntervalsArg.getValue()));
    }

    final String[] authRateArgsArray =
         authRateArgs.toArray(StaticUtils.NO_STRINGS);

    final AuthRate authRate = new AuthRate(getOut(), getErr());

    final ResultCode authRateResultCode =
         authRate.runTool(authRateArgsArray);
    if (authRateResultCode == ResultCode.SUCCESS)
    {
      final String message = "The authrate tool completed successfully.";
      completionMessage.compareAndSet(null, message);
      wrapOut(0, WRAP_COLUMN, message);
    }
    else
    {
      final String message =
           "ERROR:  The authrate tool exited with error result code " +
                authRateResultCode + '.';
      completionMessage.compareAndSet(null, message);
      wrapErr(0, WRAP_COLUMN, message);
    }

    return authRateResultCode;
  }



  /**
   * Invokes the {@link SearchAndModRate} tool with an appropriate set of
   * arguments.
   *
   * @param  listenPort  The port on which the LDAP listener is listening.
   *
   * @return  The result code obtained from the {@code SearchAndModRate} tool.
   */
  @NotNull()
  private ResultCode invokeSearchAndModRate(final int listenPort)
  {
    final List<String> searchAndModRateArgs = new ArrayList<>();

    searchAndModRateArgs.add("--hostname");
    searchAndModRateArgs.add("localhost");

    searchAndModRateArgs.add("--port");
    searchAndModRateArgs.add(String.valueOf(listenPort));

    if (useSSLArg.isPresent())
    {
      searchAndModRateArgs.add("--useSSL");
      searchAndModRateArgs.add("--trustAll");
    }

    searchAndModRateArgs.add("--baseDN");
    searchAndModRateArgs.add("dc=example,dc=com");

    searchAndModRateArgs.add("--scope");
    searchAndModRateArgs.add("sub");

    searchAndModRateArgs.add("--filter");
    searchAndModRateArgs.add("(objectClass=*)");

    searchAndModRateArgs.add("--modifyAttribute");
    searchAndModRateArgs.add("description");

    searchAndModRateArgs.add("--valueLength");
    searchAndModRateArgs.add("10");

    searchAndModRateArgs.add("--numThreads");
    searchAndModRateArgs.add(String.valueOf(numThreadsArg.getValue()));

    if (numIntervalsArg.isPresent())
    {
      searchAndModRateArgs.add("--numIntervals");
      searchAndModRateArgs.add(String.valueOf(numIntervalsArg.getValue()));
    }

    if (intervalDurationSecondsArg.isPresent())
    {
      searchAndModRateArgs.add("--intervalDuration");
      searchAndModRateArgs.add(String.valueOf(
           intervalDurationSecondsArg.getValue()));
    }

    if (warmUpIntervalsArg.isPresent())
    {
      searchAndModRateArgs.add("--warmUpIntervals");
      searchAndModRateArgs.add(String.valueOf(warmUpIntervalsArg.getValue()));
    }

    final String[] searchAndModRateArgsArray =
         searchAndModRateArgs.toArray(StaticUtils.NO_STRINGS);

    final SearchAndModRate searchAndModRate =
         new SearchAndModRate(getOut(), getErr());

    final ResultCode searchAndModRateResultCode =
         searchAndModRate.runTool(searchAndModRateArgsArray);
    if (searchAndModRateResultCode == ResultCode.SUCCESS)
    {
      final String message =
           "The search-and-mod-rate tool completed successfully.";
      completionMessage.compareAndSet(null, message);
      wrapOut(0, WRAP_COLUMN, message);
    }
    else
    {
      final String message =
           "ERROR:  The search-and-mod-rate tool exited with error result " +
                "code " + searchAndModRateResultCode + '.';
      completionMessage.compareAndSet(null, message);
      wrapErr(0, WRAP_COLUMN, message);
    }

    return searchAndModRateResultCode;
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
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples = new LinkedHashMap<>();

    examples.put(
         new String[]
         {
           "--numThreads", "10"
         },
         "Test LDAP SDK performance with the searchrate tool using ten " +
              "concurrent threads.  Communication will use an insecure " +
              "connection, and each search will return a success result with " +
              "a single matching entry.  The tool will continue to run until " +
              "it is interrupted.");

    examples.put(
         new String[]
         {
           "--tool", "modrate",
           "--numThreads", "10",
           "--useSSL",
           "--resultCode", "32",
           "--diagnosticMessage", "The base entry does not exist",
           "--warmUpIntervals", "5",
           "--numIntervals", "10",
           "--intervalDurationSeconds", "5"
         },
         "Test LDAP SDK performance with the modrate tool using ten " +
              "concurrent threads over SSL-encrypted connections.  Each " +
              "modify will return an error result with a result code of 32 " +
              "(noSuchObject) and a diagnostic message of 'The target entry " +
              "does not exist'.  The tool will run five warm-up intervals " +
              "of five seconds each, and then ten 5-second intervals in " +
              "which it will capture statistics.  The tool will exit after " +
              "those last ten intervals have completed.");

    return examples;
  }
}
