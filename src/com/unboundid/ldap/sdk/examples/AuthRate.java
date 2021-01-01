/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10RequestControl;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.OutputFormat;
import com.unboundid.util.RateAdjustor;
import com.unboundid.util.ResultCodeCounter;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ValuePattern;
import com.unboundid.util.WakeableSleeper;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a tool that can be used to test authentication processing
 * in an LDAP directory server using multiple threads.  Each authentication will
 * consist of two operations:  a search to find the target entry followed by a
 * bind to verify the credentials for that user.  The search will use the given
 * base DN and filter, either or both of which may be a value pattern as
 * described in the {@link ValuePattern} class.  This makes it possible to
 * search over a range of entries rather than repeatedly performing searches
 * with the same base DN and filter.
 * <BR><BR>
 * Some of the APIs demonstrated by this example include:
 * <UL>
 *   <LI>Argument Parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 *   <LI>LDAP Command-Line Tool (from the {@code com.unboundid.util}
 *       package)</LI>
 *   <LI>LDAP Communication (from the {@code com.unboundid.ldap.sdk}
 *       package)</LI>
 *   <LI>Value Patterns (from the {@code com.unboundid.util} package)</LI>
 * </UL>
 * Each search must match exactly one entry, and this tool will then attempt to
 * authenticate as the user associated with that entry.  It supports simple
 * authentication, as well as the CRAM-MD5, DIGEST-MD5, and PLAIN SASL
 * mechanisms.
 * <BR><BR>
 * All of the necessary information is provided using command line arguments.
 * Supported arguments include those allowed by the {@link LDAPCommandLineTool}
 * class, as well as the following additional arguments:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies the base DN to use
 *       for the searches.  This must be provided.  It may be a simple DN, or it
 *       may be a value pattern to express a range of base DNs.</LI>
 *   <LI>"-s {scope}" or "--scope {scope}" -- specifies the scope to use for the
 *       search.  The scope value should be one of "base", "one", "sub", or
 *       "subord".  If this isn't specified, then a scope of "sub" will be
 *       used.</LI>
 *   <LI>"-f {filter}" or "--filter {filter}" -- specifies the filter to use for
 *       the searches.  This must be provided.  It may be a simple filter, or it
 *       may be a value pattern to express a range of filters.</LI>
 *   <LI>"-A {name}" or "--attribute {name}" -- specifies the name of an
 *       attribute that should be included in entries returned from the server.
 *       If this is not provided, then all user attributes will be requested.
 *       This may include special tokens that the server may interpret, like
 *       "1.1" to indicate that no attributes should be returned, "*", for all
 *       user attributes, or "+" for all operational attributes.  Multiple
 *       attributes may be requested with multiple instances of this
 *       argument.</LI>
 *   <LI>"-C {password}" or "--credentials {password}" -- specifies the password
 *       to use when authenticating users identified by the searches.</LI>
 *   <LI>"-a {authType}" or "--authType {authType}" -- specifies the type of
 *       authentication to attempt.  Supported values include "SIMPLE",
 *       "CRAM-MD5", "DIGEST-MD5", and "PLAIN".
 *   <LI>"-t {num}" or "--numThreads {num}" -- specifies the number of
 *       concurrent threads to use when performing the authentication
 *       processing.  If this is not provided, then a default of one thread will
 *       be used.</LI>
 *   <LI>"-i {sec}" or "--intervalDuration {sec}" -- specifies the length of
 *       time in seconds between lines out output.  If this is not provided,
 *       then a default interval duration of five seconds will be used.</LI>
 *   <LI>"-I {num}" or "--numIntervals {num}" -- specifies the maximum number of
 *       intervals for which to run.  If this is not provided, then it will
 *       run forever.</LI>
 *   <LI>"-r {auths-per-second}" or "--ratePerSecond {auths-per-second}" --
 *       specifies the target number of authorizations to perform per second.
 *       It is still necessary to specify a sufficient number of threads for
 *       achieving this rate.  If this option is not provided, then the tool
 *       will run at the maximum rate for the specified number of threads.</LI>
 *   <LI>"--variableRateData {path}" -- specifies the path to a file containing
 *       information needed to allow the tool to vary the target rate over time.
 *       If this option is not provided, then the tool will either use a fixed
 *       target rate as specified by the "--ratePerSecond" argument, or it will
 *       run at the maximum rate.</LI>
 *   <LI>"--generateSampleRateFile {path}" -- specifies the path to a file to
 *       which sample data will be written illustrating and describing the
 *       format of the file expected to be used in conjunction with the
 *       "--variableRateData" argument.</LI>
 *   <LI>"--warmUpIntervals {num}" -- specifies the number of intervals to
 *       complete before beginning overall statistics collection.</LI>
 *   <LI>"--timestampFormat {format}" -- specifies the format to use for
 *       timestamps included before each output line.  The format may be one of
 *       "none" (for no timestamps), "with-date" (to include both the date and
 *       the time), or "without-date" (to include only time time).</LI>
 *   <LI>"--suppressErrorResultCodes" -- Indicates that information about the
 *       result codes for failed operations should not be displayed.</LI>
 *   <LI>"-c" or "--csv" -- Generate output in CSV format rather than a
 *       display-friendly format.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class AuthRate
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6918029871717330547L;



  // Indicates whether a request has been made to stop running.
  @NotNull private final AtomicBoolean stopRequested;

  // The number of authrate threads that are currently running.
  @NotNull private final AtomicInteger runningThreads;

  // The argument used to indicate that bind requests should include the
  // authorization identity request control.
  @Nullable private BooleanArgument authorizationIdentityRequestControl;

  // The argument used to indicate whether the tool should only perform a bind
  // without a search.
  @Nullable private BooleanArgument bindOnly;

  // The argument used to indicate whether to generate output in CSV format.
  @Nullable private BooleanArgument csvFormat;

  // The argument used to indicate that bind requests should include the
  // password policy request control.
  @Nullable private BooleanArgument passwordPolicyRequestControl;

  // The argument used to indicate whether to suppress information about error
  // result codes.
  @Nullable private BooleanArgument suppressErrorsArgument;

  // The argument used to specify arbitrary controls to include in bind
  // requests.
  @Nullable private ControlArgument bindControl;

  // The argument used to specify arbitrary controls to include in search
  // requests.
  @Nullable private ControlArgument searchControl;

  // The argument used to specify a variable rate file.
  @Nullable private FileArgument sampleRateFile;

  // The argument used to specify a variable rate file.
  @Nullable private FileArgument variableRateData;

  // The argument used to specify the collection interval.
  @Nullable private IntegerArgument collectionInterval;

  // The argument used to specify the number of intervals.
  @Nullable private IntegerArgument numIntervals;

  // The argument used to specify the number of threads.
  @Nullable private IntegerArgument numThreads;

  // The argument used to specify the seed to use for the random number
  // generator.
  @Nullable private IntegerArgument randomSeed;

  // The target rate of authentications per second.
  @Nullable private IntegerArgument ratePerSecond;

  // The number of warm-up intervals to perform.
  @Nullable private IntegerArgument warmUpIntervals;

  // The argument used to specify the attributes to return.
  @Nullable private StringArgument attributes;

  // The argument used to specify the type of authentication to perform.
  @Nullable private StringArgument authType;

  // The argument used to specify the base DNs for the searches.
  @Nullable private StringArgument baseDN;

  // The argument used to specify the filters for the searches.
  @Nullable private StringArgument filter;

  // The argument used to specify the scope for the searches.
  @Nullable private ScopeArgument scopeArg;

  // The argument used to specify the timestamp format.
  @Nullable private StringArgument timestampFormat;

  // The argument used to specify the password to use to authenticate.
  @Nullable private StringArgument userPassword;

  // A wakeable sleeper that will be used to sleep between reporting intervals.
  @NotNull private final WakeableSleeper sleeper;



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
    final AuthRate authRate = new AuthRate(outStream, errStream);
    return authRate.runTool(args);
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
  public AuthRate(@Nullable final OutputStream outStream,
                  @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    stopRequested = new AtomicBoolean(false);
    runningThreads = new AtomicInteger(0);
    sleeper = new WakeableSleeper();
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
    return "authrate";
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
    return "Perform repeated authentications against an LDAP directory " +
           "server, where each authentication consists of a search to " +
           "find a user followed by a bind to verify the credentials " +
           "for that user.";
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
    String description = "The base DN to use for the searches.  It may be a " +
         "simple DN or a value pattern to specify a range of DNs (e.g., " +
         "\"uid=user.[1-1000],ou=People,dc=example,dc=com\").  See " +
         ValuePattern.PUBLIC_JAVADOC_URL + " for complete details about the " +
         "value pattern syntax.  This must be provided.";
    baseDN = new StringArgument('b', "baseDN", true, 1, "{dn}", description);
    baseDN.setArgumentGroupName("Search and Authentication Arguments");
    baseDN.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDN);


    description = "The scope to use for the searches.  It should be 'base', " +
                  "'one', 'sub', or 'subord'.  If this is not provided, a " +
                  "default scope of 'sub' will be used.";
    scopeArg = new ScopeArgument('s', "scope", false, "{scope}", description,
                                 SearchScope.SUB);
    scopeArg.setArgumentGroupName("Search and Authentication Arguments");
    parser.addArgument(scopeArg);


    description = "The filter to use for the searches.  It may be a simple " +
                  "filter or a value pattern to specify a range of filters " +
                  "(e.g., \"(uid=user.[1-1000])\").  See " +
                  ValuePattern.PUBLIC_JAVADOC_URL + " for complete details " +
                  "about the value pattern syntax.  This must be provided.";
    filter = new StringArgument('f', "filter", false, 1, "{filter}",
                                description);
    filter.setArgumentGroupName("Search and Authentication Arguments");
    parser.addArgument(filter);


    description = "The name of an attribute to include in entries returned " +
                  "from the searches.  Multiple attributes may be requested " +
                  "by providing this argument multiple times.  If no return " +
                  "attributes are specified, then entries will be returned " +
                  "with all user attributes.";
    attributes = new StringArgument('A', "attribute", false, 0, "{name}",
                                    description);
    attributes.setArgumentGroupName("Search and Authentication Arguments");
    parser.addArgument(attributes);


    description = "The password to use when binding as the users returned " +
                  "from the searches.  This must be provided.";
    userPassword = new StringArgument('C', "credentials", true, 1, "{password}",
                                      description);
    userPassword.setSensitive(true);
    userPassword.setArgumentGroupName("Search and Authentication Arguments");
    parser.addArgument(userPassword);


    description = "Indicates that the tool should only perform bind " +
                  "operations without the initial search.  If this argument " +
                  "is provided, then the base DN pattern will be used to " +
                  "obtain the bind DNs.";
    bindOnly = new BooleanArgument('B', "bindOnly", 1, description);
    bindOnly.setArgumentGroupName("Search and Authentication Arguments");
    bindOnly.addLongIdentifier("bind-only", true);
    parser.addArgument(bindOnly);
    parser.addRequiredArgumentSet(filter, bindOnly);


    description = "The type of authentication to perform.  Allowed values " +
                  "are:  SIMPLE, CRAM-MD5, DIGEST-MD5, and PLAIN.  If no "+
                  "value is provided, then SIMPLE authentication will be " +
                  "performed.";
    final Set<String> allowedAuthTypes =
         StaticUtils.setOf("simple", "cram-md5", "digest-md5", "plain");
    authType = new StringArgument('a', "authType", true, 1, "{authType}",
                                  description, allowedAuthTypes, "simple");
    authType.setArgumentGroupName("Search and Authentication Arguments");
    authType.addLongIdentifier("auth-type", true);
    parser.addArgument(authType);


    description = "Indicates that bind requests should include the " +
                  "authorization identity request control as described in " +
                  "RFC 3829.";
    authorizationIdentityRequestControl = new BooleanArgument(null,
         "authorizationIdentityRequestControl", 1, description);
    authorizationIdentityRequestControl.setArgumentGroupName(
         "Request Control Arguments");
    authorizationIdentityRequestControl.addLongIdentifier(
         "authorization-identity-request-control", true);
    parser.addArgument(authorizationIdentityRequestControl);


    description = "Indicates that bind requests should include the " +
                  "password policy request control as described in " +
                  "draft-behera-ldap-password-policy-10.";
    passwordPolicyRequestControl = new BooleanArgument(null,
         "passwordPolicyRequestControl", 1, description);
    passwordPolicyRequestControl.setArgumentGroupName(
         "Request Control Arguments");
    passwordPolicyRequestControl.addLongIdentifier(
         "password-policy-request-control", true);
    parser.addArgument(passwordPolicyRequestControl);


    description = "Indicates that search requests should include the " +
                  "specified request control.  This may be provided multiple " +
                  "times to include multiple search request controls.";
    searchControl = new ControlArgument(null, "searchControl", false, 0, null,
                                        description);
    searchControl.setArgumentGroupName("Request Control Arguments");
    searchControl.addLongIdentifier("search-control", true);
    parser.addArgument(searchControl);


    description = "Indicates that bind requests should include the " +
                  "specified request control.  This may be provided multiple " +
                  "times to include multiple modify request controls.";
    bindControl = new ControlArgument(null, "bindControl", false, 0, null,
                                      description);
    bindControl.setArgumentGroupName("Request Control Arguments");
    bindControl.addLongIdentifier("bind-control", true);
    parser.addArgument(bindControl);


    description = "The number of threads to use to perform the " +
                  "authentication processing.  If this is not provided, then " +
                  "a default of one thread will be used.";
    numThreads = new IntegerArgument('t', "numThreads", true, 1, "{num}",
                                     description, 1, Integer.MAX_VALUE, 1);
    numThreads.setArgumentGroupName("Rate Management Arguments");
    numThreads.addLongIdentifier("num-threads", true);
    parser.addArgument(numThreads);


    description = "The length of time in seconds between output lines.  If " +
                  "this is not provided, then a default interval of five " +
                  "seconds will be used.";
    collectionInterval = new IntegerArgument('i', "intervalDuration", true, 1,
                                             "{num}", description, 1,
                                             Integer.MAX_VALUE, 5);
    collectionInterval.setArgumentGroupName("Rate Management Arguments");
    collectionInterval.addLongIdentifier("interval-duration", true);
    parser.addArgument(collectionInterval);


    description = "The maximum number of intervals for which to run.  If " +
                  "this is not provided, then the tool will run until it is " +
                  "interrupted.";
    numIntervals = new IntegerArgument('I', "numIntervals", true, 1, "{num}",
                                       description, 1, Integer.MAX_VALUE,
                                       Integer.MAX_VALUE);
    numIntervals.setArgumentGroupName("Rate Management Arguments");
    numIntervals.addLongIdentifier("num-intervals", true);
    parser.addArgument(numIntervals);

    description = "The target number of authorizations to perform per " +
                  "second.  It is still necessary to specify a sufficient " +
                  "number of threads for achieving this rate.  If neither " +
                  "this option nor --variableRateData is provided, then the " +
                  "tool will run at the maximum rate for the specified " +
                  "number of threads.";
    ratePerSecond = new IntegerArgument('r', "ratePerSecond", false, 1,
                                        "{auths-per-second}", description,
                                        1, Integer.MAX_VALUE);
    ratePerSecond.setArgumentGroupName("Rate Management Arguments");
    ratePerSecond.addLongIdentifier("rate-per-second", true);
    parser.addArgument(ratePerSecond);

    final String variableRateDataArgName = "variableRateData";
    final String generateSampleRateFileArgName = "generateSampleRateFile";
    description = RateAdjustor.getVariableRateDataArgumentDescription(
         generateSampleRateFileArgName);
    variableRateData = new FileArgument(null, variableRateDataArgName, false, 1,
                                        "{path}", description, true, true, true,
                                        false);
    variableRateData.setArgumentGroupName("Rate Management Arguments");
    variableRateData.addLongIdentifier("variable-rate-data", true);
    parser.addArgument(variableRateData);

    description = RateAdjustor.getGenerateSampleVariableRateFileDescription(
         variableRateDataArgName);
    sampleRateFile = new FileArgument(null, generateSampleRateFileArgName,
                                      false, 1, "{path}", description, false,
                                      true, true, false);
    sampleRateFile.setArgumentGroupName("Rate Management Arguments");
    sampleRateFile.addLongIdentifier("generate-sample-rate-file", true);
    sampleRateFile.setUsageArgument(true);
    parser.addArgument(sampleRateFile);
    parser.addExclusiveArgumentSet(variableRateData, sampleRateFile);

    description = "The number of intervals to complete before beginning " +
                  "overall statistics collection.  Specifying a nonzero " +
                  "number of warm-up intervals gives the client and server " +
                  "a chance to warm up without skewing performance results.";
    warmUpIntervals = new IntegerArgument(null, "warmUpIntervals", true, 1,
         "{num}", description, 0, Integer.MAX_VALUE, 0);
    warmUpIntervals.setArgumentGroupName("Rate Management Arguments");
    warmUpIntervals.addLongIdentifier("warm-up-intervals", true);
    parser.addArgument(warmUpIntervals);

    description = "Indicates the format to use for timestamps included in " +
                  "the output.  A value of 'none' indicates that no " +
                  "timestamps should be included.  A value of 'with-date' " +
                  "indicates that both the date and the time should be " +
                  "included.  A value of 'without-date' indicates that only " +
                  "the time should be included.";
    final Set<String> allowedFormats =
         StaticUtils.setOf("none", "with-date", "without-date");
    timestampFormat = new StringArgument(null, "timestampFormat", true, 1,
         "{format}", description, allowedFormats, "none");
    timestampFormat.addLongIdentifier("timestamp-format", true);
    parser.addArgument(timestampFormat);

    description = "Indicates that information about the result codes for " +
                  "failed operations should not be displayed.";
    suppressErrorsArgument = new BooleanArgument(null,
         "suppressErrorResultCodes", 1, description);
    suppressErrorsArgument.addLongIdentifier("suppress-error-result-codes",
         true);
    parser.addArgument(suppressErrorsArgument);

    description = "Generate output in CSV format rather than a " +
                  "display-friendly format";
    csvFormat = new BooleanArgument('c', "csv", 1, description);
    parser.addArgument(csvFormat);

    description = "Specifies the seed to use for the random number generator.";
    randomSeed = new IntegerArgument('R', "randomSeed", false, 1, "{value}",
         description);
    randomSeed.addLongIdentifier("random-seed", true);
    parser.addArgument(randomSeed);
  }



  /**
   * Indicates whether this tool supports creating connections to multiple
   * servers.  If it is to support multiple servers, then the "--hostname" and
   * "--port" arguments will be allowed to be provided multiple times, and
   * will be required to be provided the same number of times.  The same type of
   * communication security and bind credentials will be used for all servers.
   *
   * @return  {@code true} if this tool supports creating connections to
   *          multiple servers, or {@code false} if not.
   */
  @Override()
  protected boolean supportsMultipleServers()
  {
    return true;
  }



  /**
   * Retrieves the connection options that should be used for connections
   * created for use with this tool.
   *
   * @return  The connection options that should be used for connections created
   *          for use with this tool.
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    return options;
  }



  /**
   * Performs the actual processing for this tool.  In this case, it gets a
   * connection to the directory server and uses it to perform the requested
   * searches.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // If the sample rate file argument was specified, then generate the sample
    // variable rate data file and return.
    if (sampleRateFile.isPresent())
    {
      try
      {
        RateAdjustor.writeSampleVariableRateFile(sampleRateFile.getValue());
        return ResultCode.SUCCESS;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err("An error occurred while trying to write sample variable data " +
             "rate file '", sampleRateFile.getValue().getAbsolutePath(),
             "':  ", StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Determine the random seed to use.
    final Long seed;
    if (randomSeed.isPresent())
    {
      seed = Long.valueOf(randomSeed.getValue());
    }
    else
    {
      seed = null;
    }

    // Create value patterns for the base DN and filter.
    final ValuePattern dnPattern;
    try
    {
      dnPattern = new ValuePattern(baseDN.getValue(), seed);
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      err("Unable to parse the base DN value pattern:  ", pe.getMessage());
      return ResultCode.PARAM_ERROR;
    }

    final ValuePattern filterPattern;
    if (filter.isPresent())
    {
      try
      {
        filterPattern = new ValuePattern(filter.getValue(), seed);
      }
      catch (final ParseException pe)
      {
        Debug.debugException(pe);
        err("Unable to parse the filter pattern:  ", pe.getMessage());
        return ResultCode.PARAM_ERROR;
      }
    }
    else
    {
      filterPattern = null;
    }


    // Get the attributes to return.
    final String[] attrs;
    if (attributes.isPresent())
    {
      final List<String> attrList = attributes.getValues();
      attrs = new String[attrList.size()];
      attrList.toArray(attrs);
    }
    else
    {
      attrs = StaticUtils.NO_STRINGS;
    }


    // If the --ratePerSecond option was specified, then limit the rate
    // accordingly.
    FixedRateBarrier fixedRateBarrier = null;
    if (ratePerSecond.isPresent() || variableRateData.isPresent())
    {
      // We might not have a rate per second if --variableRateData is specified.
      // The rate typically doesn't matter except when we have warm-up
      // intervals.  In this case, we'll run at the max rate.
      final int intervalSeconds = collectionInterval.getValue();
      final int ratePerInterval =
           (ratePerSecond.getValue() == null)
           ? Integer.MAX_VALUE
           : ratePerSecond.getValue() * intervalSeconds;
      fixedRateBarrier =
           new FixedRateBarrier(1000L * intervalSeconds, ratePerInterval);
    }


    // If --variableRateData was specified, then initialize a RateAdjustor.
    RateAdjustor rateAdjustor = null;
    if (variableRateData.isPresent())
    {
      try
      {
        rateAdjustor = RateAdjustor.newInstance(fixedRateBarrier,
             ratePerSecond.getValue(), variableRateData.getValue());
      }
      catch (final IOException | IllegalArgumentException e)
      {
        Debug.debugException(e);
        err("Initializing the variable rates failed: " + e.getMessage());
        return ResultCode.PARAM_ERROR;
      }
    }


    // Determine whether to include timestamps in the output and if so what
    // format should be used for them.
    final boolean includeTimestamp;
    final String timeFormat;
    if (timestampFormat.getValue().equalsIgnoreCase("with-date"))
    {
      includeTimestamp = true;
      timeFormat       = "dd/MM/yyyy HH:mm:ss";
    }
    else if (timestampFormat.getValue().equalsIgnoreCase("without-date"))
    {
      includeTimestamp = true;
      timeFormat       = "HH:mm:ss";
    }
    else
    {
      includeTimestamp = false;
      timeFormat       = null;
    }


    // Get the controls to include in bind requests.
    final ArrayList<Control> bindControls = new ArrayList<>(5);
    if (authorizationIdentityRequestControl.isPresent())
    {
      bindControls.add(new AuthorizationIdentityRequestControl());
    }

    if (passwordPolicyRequestControl.isPresent())
    {
      bindControls.add(new DraftBeheraLDAPPasswordPolicy10RequestControl());
    }

    bindControls.addAll(bindControl.getValues());


    // Determine whether any warm-up intervals should be run.
    final long totalIntervals;
    final boolean warmUp;
    int remainingWarmUpIntervals = warmUpIntervals.getValue();
    if (remainingWarmUpIntervals > 0)
    {
      warmUp = true;
      totalIntervals = 0L + numIntervals.getValue() + remainingWarmUpIntervals;
    }
    else
    {
      warmUp = true;
      totalIntervals = 0L + numIntervals.getValue();
    }


    // Create the table that will be used to format the output.
    final OutputFormat outputFormat;
    if (csvFormat.isPresent())
    {
      outputFormat = OutputFormat.CSV;
    }
    else
    {
      outputFormat = OutputFormat.COLUMNS;
    }

    final ColumnFormatter formatter = new ColumnFormatter(includeTimestamp,
         timeFormat, outputFormat, " ",
         new FormattableColumn(12, HorizontalAlignment.RIGHT, "Recent",
                  "Auths/Sec"),
         new FormattableColumn(12, HorizontalAlignment.RIGHT, "Recent",
                  "Avg Dur ms"),
         new FormattableColumn(12, HorizontalAlignment.RIGHT, "Recent",
                  "Errors/Sec"),
         new FormattableColumn(12, HorizontalAlignment.RIGHT, "Overall",
                  "Auths/Sec"),
         new FormattableColumn(12, HorizontalAlignment.RIGHT, "Overall",
                  "Avg Dur ms"));


    // Create values to use for statistics collection.
    final AtomicLong        authCounter   = new AtomicLong(0L);
    final AtomicLong        errorCounter  = new AtomicLong(0L);
    final AtomicLong        authDurations = new AtomicLong(0L);
    final ResultCodeCounter rcCounter     = new ResultCodeCounter();


    // Determine the length of each interval in milliseconds.
    final long intervalMillis = 1000L * collectionInterval.getValue();


    // Create the threads to use for the searches.
    final CyclicBarrier barrier = new CyclicBarrier(numThreads.getValue() + 1);
    final AuthRateThread[] threads = new AuthRateThread[numThreads.getValue()];
    for (int i=0; i < threads.length; i++)
    {
      final LDAPConnection searchConnection;
      final LDAPConnection bindConnection;
      try
      {
        searchConnection = getConnection();
        bindConnection   = getConnection();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err("Unable to connect to the directory server:  ",
            StaticUtils.getExceptionMessage(le));
        return le.getResultCode();
      }

      threads[i] = new AuthRateThread(this, i, searchConnection, bindConnection,
           dnPattern, scopeArg.getValue(), filterPattern, attrs,
           userPassword.getValue(), bindOnly.isPresent(), authType.getValue(),
           searchControl.getValues(), bindControls, runningThreads, barrier,
           authCounter, authDurations, errorCounter, rcCounter,
           fixedRateBarrier);
      threads[i].start();
    }


    // Display the table header.
    for (final String headerLine : formatter.getHeaderLines(true))
    {
      out(headerLine);
    }


    // Start the RateAdjustor before the threads so that the initial value is
    // in place before any load is generated unless we're doing a warm-up in
    // which case, we'll start it after the warm-up is complete.
    if ((rateAdjustor != null) && (remainingWarmUpIntervals <= 0))
    {
      rateAdjustor.start();
    }


    // Indicate that the threads can start running.
    try
    {
      barrier.await();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    long overallStartTime = System.nanoTime();
    long nextIntervalStartTime = System.currentTimeMillis() + intervalMillis;


    boolean setOverallStartTime = false;
    long    lastDuration        = 0L;
    long    lastNumErrors       = 0L;
    long    lastNumAuths        = 0L;
    long    lastEndTime         = System.nanoTime();
    for (long i=0; i < totalIntervals; i++)
    {
      if (rateAdjustor != null)
      {
        if (! rateAdjustor.isAlive())
        {
          out("All of the rates in " + variableRateData.getValue().getName() +
              " have been completed.");
          break;
        }
      }

      final long startTimeMillis = System.currentTimeMillis();
      final long sleepTimeMillis = nextIntervalStartTime - startTimeMillis;
      nextIntervalStartTime += intervalMillis;
      if (sleepTimeMillis > 0)
      {
        sleeper.sleep(sleepTimeMillis);
      }

      if (stopRequested.get())
      {
        break;
      }

      final long endTime          = System.nanoTime();
      final long intervalDuration = endTime - lastEndTime;

      final long numAuths;
      final long numErrors;
      final long totalDuration;
      if (warmUp && (remainingWarmUpIntervals > 0))
      {
        numAuths      = authCounter.getAndSet(0L);
        numErrors     = errorCounter.getAndSet(0L);
        totalDuration = authDurations.getAndSet(0L);
      }
      else
      {
        numAuths      = authCounter.get();
        numErrors     = errorCounter.get();
        totalDuration = authDurations.get();
      }

      final long recentNumAuths  = numAuths - lastNumAuths;
      final long recentNumErrors = numErrors - lastNumErrors;
      final long recentDuration = totalDuration - lastDuration;

      final double numSeconds = intervalDuration / 1_000_000_000.0d;
      final double recentAuthRate = recentNumAuths / numSeconds;
      final double recentErrorRate  = recentNumErrors / numSeconds;

      final double recentAvgDuration;
      if (recentNumAuths > 0L)
      {
        recentAvgDuration = 1.0d * recentDuration / recentNumAuths / 1_000_000;
      }
      else
      {
        recentAvgDuration = 0.0d;
      }

      if (warmUp && (remainingWarmUpIntervals > 0))
      {
        out(formatter.formatRow(recentAuthRate, recentAvgDuration,
             recentErrorRate, "warming up", "warming up"));

        remainingWarmUpIntervals--;
        if (remainingWarmUpIntervals == 0)
        {
          out("Warm-up completed.  Beginning overall statistics collection.");
          setOverallStartTime = true;
          if (rateAdjustor != null)
          {
            rateAdjustor.start();
          }
        }
      }
      else
      {
        if (setOverallStartTime)
        {
          overallStartTime    = lastEndTime;
          setOverallStartTime = false;
        }

        final double numOverallSeconds =
             (endTime - overallStartTime) / 1_000_000_000.0d;
        final double overallAuthRate = numAuths / numOverallSeconds;

        final double overallAvgDuration;
        if (numAuths > 0L)
        {
          overallAvgDuration = 1.0d * totalDuration / numAuths / 1_000_000;
        }
        else
        {
          overallAvgDuration = 0.0d;
        }

        out(formatter.formatRow(recentAuthRate, recentAvgDuration,
             recentErrorRate, overallAuthRate, overallAvgDuration));

        lastNumAuths    = numAuths;
        lastNumErrors   = numErrors;
        lastDuration    = totalDuration;
      }

      final List<ObjectPair<ResultCode,Long>> rcCounts =
           rcCounter.getCounts(true);
      if ((! suppressErrorsArgument.isPresent()) && (! rcCounts.isEmpty()))
      {
        err("\tError Results:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          err("\t", p.getFirst().getName(), ":  ", p.getSecond());
        }
      }

      lastEndTime = endTime;
    }


    // Shut down the RateAdjustor if we have one.
    if (rateAdjustor != null)
    {
      rateAdjustor.shutDown();
    }


    // Stop all of the threads.
    ResultCode resultCode = ResultCode.SUCCESS;
    for (final AuthRateThread t : threads)
    {
      final ResultCode r = t.stopRunning();
      if (resultCode == ResultCode.SUCCESS)
      {
        resultCode = r;
      }
    }

    return resultCode;
  }



  /**
   * Requests that this tool stop running.  This method will attempt to wait
   * for all threads to complete before returning control to the caller.
   */
  public void stopRunning()
  {
    stopRequested.set(true);
    sleeper.wakeup();

    while (true)
    {
      final int stillRunning = runningThreads.get();
      if (stillRunning <= 0)
      {
        break;
      }
      else
      {
        try
        {
          Thread.sleep(1L);
        } catch (final Exception e) {}
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));

    String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "dc=example,dc=com",
      "--scope", "sub",
      "--filter", "(uid=user.[1-1000000])",
      "--credentials", "password",
      "--numThreads", "10"
    };
    String description =
         "Test authentication performance by searching randomly across a set " +
         "of one million users located below 'dc=example,dc=com' with ten " +
         "concurrent threads and performing simple binds with a password of " +
         "'password'.  The searches will be performed anonymously.";
    examples.put(args, description);

    args = new String[]
    {
      "--generateSampleRateFile", "variable-rate-data.txt"
    };
    description =
         "Generate a sample variable rate definition file that may be used " +
         "in conjunction with the --variableRateData argument.  The sample " +
         "file will include comments that describe the format for data to be " +
         "included in this file.";
    examples.put(args, description);

    return examples;
  }
}
