/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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



import java.io.OutputStream;
import java.io.Serializable;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ValuePattern;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.util.StaticUtils.*;



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
 *   <LI>"-r {auths-per-second}" or "--ratePerSecond {auths-per-second}"
 *       specifies the target number of authorizations to perform per second.
 *       It is still necessary to specify a sufficient number of threads for
 *       achieving this rate.  If this option is not provided, then the tool
 *       will run at the maximum rate for the specified number of threads.</LI>
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



  // The argument used to indicate whether to generate output in CSV format.
  private BooleanArgument csvFormat;

  // The argument used to specify the collection interval.
  private IntegerArgument collectionInterval;

  // The argument used to specify the number of intervals.
  private IntegerArgument numIntervals;

  // The argument used to specify the number of threads.
  private IntegerArgument numThreads;

  // The target rate of auths per second.
  private IntegerArgument ratePerSecond;

  // The argument used to specify the attributes to return.
  private StringArgument attributes;

  // The argument used to specify the type of authentication to perform.
  private StringArgument authType;

  // The argument used to specify the base DNs for the searches.
  private StringArgument baseDN;

  // The argument used to specify the filters for the searches.
  private StringArgument filter;

  // The argument used to specify the scope for the searches.
  private StringArgument scopeStr;

  // The argument used to specify the password to use to authenticate.
  private StringArgument userPassword;



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
  public AuthRate(final OutputStream outStream, final OutputStream errStream)
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
    return "authrate";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Perform repeated authentications against an LDAP directory " +
           "server, where each authentication consists of a search to " +
           "find a user followed by a bind to verify the credentials " +
           "for that user.";
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
    String description = "The base DN to use for the searches.  It may be a " +
         "simple DN or a value pattern to specify a range of DNs (e.g., " +
         "\"uid=user.[1-1000],ou=People,dc=example,dc=com\").  This must be " +
         "provided.";
    baseDN = new StringArgument('b', "baseDN", true, 1, "{dn}", description);
    parser.addArgument(baseDN);


    description = "The scope to use for the searches.  It should be 'base', " +
                  "'one', 'sub', or 'subord'.  If this is not provided, a " +
                  "default scope of 'sub' will be used.";
    final LinkedHashSet<String> allowedScopes = new LinkedHashSet<String>(4);
    allowedScopes.add("base");
    allowedScopes.add("one");
    allowedScopes.add("sub");
    allowedScopes.add("subord");
    scopeStr = new StringArgument('s', "scope", false, 1, "{scope}",
                                  description, allowedScopes, "sub");
    parser.addArgument(scopeStr);


    description = "The filter to use for the searches.  It may be a simple " +
                  "filter or a value pattern to specify a range of filters " +
                  "(e.g., \"(uid=user.[1-1000])\").  This must be provided.";
    filter = new StringArgument('f', "filter", true, 1, "{filter}",
                                description);
    parser.addArgument(filter);


    description = "The name of an attribute to include in entries returned " +
                  "from the searches.  Multiple attributes may be requested " +
                  "by providing this argument multiple times.  If no return " +
                  "attributes are specified, then entries will be returned " +
                  "with all user attributes.";
    attributes = new StringArgument('A', "attribute", false, 0, "{name}",
                                    description);
    parser.addArgument(attributes);


    description = "The password to use when binding as the users returned " +
                  "from the searches.  This must be provided.";
    userPassword = new StringArgument('C', "credentials", true, 1, "{password}",
                                      description);
    parser.addArgument(userPassword);


    description = "The type of authentication to perform.  Allowed values " +
                  "are:  SIMPLE, CRAM-MD5, DIGEST-MD5, and PLAIN.  If no "+
                  "value is provided, then SIMPLE authentication will be " +
                  "performed.";
    final LinkedHashSet<String> allowedAuthTypes = new LinkedHashSet<String>(4);
    allowedAuthTypes.add("simple");
    allowedAuthTypes.add("cram-md5");
    allowedAuthTypes.add("digest-md5");
    allowedAuthTypes.add("plain");
    authType = new StringArgument('a', "authType", true, 1, "{authType}",
                                  description, allowedAuthTypes, "simple");
    parser.addArgument(authType);


    description = "The number of threads to use to perform the " +
                  "authentication processing.  If this is not provided, then " +
                  "a default of one thread will be used.";
    numThreads = new IntegerArgument('t', "numThreads", true, 1, "{num}",
                                     description, 1, Integer.MAX_VALUE, 1);
    parser.addArgument(numThreads);


    description = "The length of time in seconds between output lines.  If " +
                  "this is not provided, then a default interval of five " +
                  "seconds will be used.";
    collectionInterval = new IntegerArgument('i', "intervalDuration", true, 1,
                                             "{num}", description, 1,
                                             Integer.MAX_VALUE, 5);
    parser.addArgument(collectionInterval);


    description = "The maximum number of intervals for which to run.  If " +
                  "this is not provided, then the tool will run until it is " +
                  "interrupted.";
    numIntervals = new IntegerArgument('I', "numIntervals", true, 1, "{num}",
                                       description, 1, Integer.MAX_VALUE,
                                       Integer.MAX_VALUE);
    parser.addArgument(numIntervals);

    description = "The target number of authorizations to perform per " +
                  "second.  It is still necessary to specify a sufficient " +
                  "number of threads for achieving this rate.  If this " +
                  "option is not provided, then the tool will run at the " +
                  "maximum rate for the specified number of threads.";
    ratePerSecond = new IntegerArgument('r', "ratePerSecond", false, 1,
                                        "{auths-per-second}", description,
                                        1, Integer.MAX_VALUE);
    parser.addArgument(ratePerSecond);

    description = "Generate output in CSV format rather than a " +
                  "display-friendly format";
    csvFormat = new BooleanArgument('c', "csv", 1, description);
    parser.addArgument(csvFormat);
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
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setAutoReconnect(true);
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
  public ResultCode doToolProcessing()
  {
    // Convert the search scope from a string to an integer.
    final SearchScope scope;
    if (scopeStr.getValue().equalsIgnoreCase("base"))
    {
      scope = SearchScope.BASE;
    }
    else if (scopeStr.getValue().equalsIgnoreCase("one"))
    {
      scope = SearchScope.ONE;
    }
    else if (scopeStr.getValue().equalsIgnoreCase("subord"))
    {
      scope = SearchScope.SUBORDINATE_SUBTREE;
    }
    else
    {
      scope = SearchScope.SUB;
    }


    // Create value patterns for the base DN and filter.
    final ValuePattern dnPattern;
    try
    {
      dnPattern = new ValuePattern(baseDN.getValue());
    }
    catch (ParseException pe)
    {
      err("Unable to parse the base DN value pattern:  ", pe.getMessage());
      return ResultCode.PARAM_ERROR;
    }

    final ValuePattern filterPattern;
    try
    {
      filterPattern = new ValuePattern(filter.getValue());
    }
    catch (ParseException pe)
    {
      err("Unable to parse the filter pattern:  ", pe.getMessage());
      return ResultCode.PARAM_ERROR;
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
      attrs = new String[0];
    }


    // If the --ratePerSecond option was specified, then limit the rate
    // accordingly.
    FixedRateBarrier fixedRateBarrier = null;
    if (ratePerSecond.isPresent())
    {
      final int ONE_SECOND = 1000;  // in milliseconds
      fixedRateBarrier = new FixedRateBarrier(ONE_SECOND,
                                              ratePerSecond.getValue());
    }


    // Create values to use for statistics collection.
    final AtomicLong searchCounter   = new AtomicLong(0L);
    final AtomicLong errorCounter    = new AtomicLong(0L);
    final AtomicLong searchDurations = new AtomicLong(0L);


    // Create the output formatters.
    final DecimalFormat longFormatter   = new DecimalFormat("0");
    final DecimalFormat doubleFormatter = new DecimalFormat("0.000");


    // Get the length of time to sleep in milliseconds.
    final long sleepTimeMillis = 1000L * collectionInterval.getValue();


    // Create the threads to use for the searches.
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
      catch (LDAPException le)
      {
        err("Unable to connect to the directory server:  ",
            getExceptionMessage(le));
        return le.getResultCode();
      }

      threads[i] = new AuthRateThread(i, searchConnection, bindConnection,
           dnPattern, scope, filterPattern, attrs, userPassword.getValue(),
           authType.getValue(), searchCounter, searchDurations, errorCounter,
           fixedRateBarrier);
    }


    // Start all of the threads.
    final long overallStartTime = System.nanoTime();
    for (final AuthRateThread t : threads)
    {
      t.start();
    }


    long lastDuration    = 0L;
    long lastNumErrors   = 0L;
    long lastNumSearches = 0L;
    for (int i=0; i < numIntervals.getValue(); i++)
    {
      final long startTime = System.nanoTime();
      try
      {
        Thread.sleep(sleepTimeMillis);
      } catch (Exception e) {}

      final long endTime          = System.nanoTime();
      final long intervalDuration = endTime - startTime;

      final long numSearches   = searchCounter.get();
      final long numErrors     = errorCounter.get();
      final long totalDuration = searchDurations.get();

      final long recentNumSearches = numSearches - lastNumSearches;
      final long recentNumErrors = numErrors - lastNumErrors;
      final long recentDuration = totalDuration - lastDuration;

      final double numSeconds = intervalDuration / 1000000000.0D;
      final double recentSearchRate = recentNumSearches / numSeconds;
      final double recentErrorRate  = recentNumErrors / numSeconds;
      final double recentAvgDuration =
                  1.0D * recentDuration / recentNumSearches / 1000000;

      final double numOverallSeconds =
           (endTime - overallStartTime) / 1000000000.0D;
      final double overallSearchRate = numSearches / numOverallSeconds;
      final double overallAvgDuration =
           1.0D * totalDuration / numSearches / 1000000;

      if (csvFormat.isPresent())
      {
        if (i == 0)
        {
          out("\"Recent Auths/Second\",",
              "\"Recent Average Auth Duration (ms)\",",
              "\"Recent Errors/Second\",",
              "\"Overall Auths/Second\",",
              "\"Overall Average Auth Duration (ms)\"");
        }

        out(longFormatter.format(recentSearchRate), ',',
            doubleFormatter.format(recentAvgDuration), ',',
            doubleFormatter.format(recentErrorRate), ',',
            longFormatter.format(overallSearchRate), ',',
            doubleFormatter.format(overallAvgDuration));
      }
      else
      {
        if (i == 0)
        {
          out("       Recent",
              "       Recent",
              "       Recent",
              "      Overall",
              "      Overall");
          out("    Auths/Sec",
              "   Avg Dur ms",
              "   Errors/Sec",
              "    Auths/Sec",
              "   Avg Dur ms");
          out(" ------------",
              " ------------",
              " ------------",
              " ------------",
              " ------------");
        }

        out(formatAndAlign(recentSearchRate, longFormatter),
            formatAndAlign(recentAvgDuration, doubleFormatter),
            formatAndAlign(recentErrorRate,  doubleFormatter),
            formatAndAlign(overallSearchRate, longFormatter),
            formatAndAlign(overallAvgDuration, doubleFormatter));
      }

      lastNumSearches = numSearches;
      lastNumErrors   = numErrors;
      lastDuration    = totalDuration;
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
   * Right-aligns the provided value in 13 spaces with the given formatter.
   *
   * @param  v  The value to be formatted and aligned.
   * @param  f  The formatter to use.
   *
   * @return  The formatted and aligned value.
   */
  private static String formatAndAlign(final double v, final DecimalFormat f)
  {
    final StringBuilder buffer = new StringBuilder(13);
    final String s = f.format(v);

    final int padChars = 13 - s.length();
    for (int i=0; i < padChars; i++)
    {
      buffer.append(' ');
    }
    buffer.append(s);

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>(1);

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--baseDN", "dc=example,dc=com",
      "--scope", "sub",
      "--filter", "(uid=user.[1-1000000])",
      "--credentials", "password",
      "--numThreads", "10"
    };
    final String description =
         "Test authentication performance by searching randomly across a set " +
         "of one million users located below 'dc=example,dc=com' with ten " +
         "concurrent threads and performing simple binds with a password of " +
         "'password'.  The searches will be performed anonymously.";
    examples.put(args, description);

    return examples;
  }
}
