/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
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
 * This class provides a tool that can be used to perform repeated modifications
 * in an LDAP directory server using multiple threads.  It can help provide an
 * estimate of the modify performance that a directory server is able to
 * achieve.  The target entry DN may be a value pattern as described in the
 * {@link ValuePattern} class.  This makes it possible to modify a range of
 * entries rather than repeatedly updating the same entry.
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
 * <BR><BR>
 * All of the necessary information is provided using command line arguments.
 * Supported arguments include those allowed by the {@link LDAPCommandLineTool}
 * class, as well as the following additional arguments:
 * <UL>
 *   <LI>"-b {entryDN}" or "--targetDN {baseDN}" -- specifies the DN of the
 *       entry to be modified.  This must be provided.  It may be a simple DN,
 *       or it may be a value pattern to express a range of entry DNs.</LI>
 *   <LI>"-A {name}" or "--attribute {name}" -- specifies the name of the
 *       attribute to modify.  Multiple attributes may be modified by providing
 *       multiple instances of this argument.  At least one attribute must be
 *       provided.</LI>
 *   <LI>"-l {num}" or "--valueLength {num}" -- specifies the length in bytes to
 *       use for the values of the target attributes.  If this is not provided,
 *       then a default length of 10 bytes will be used.</LI>
 *   <LI>"-C {chars}" or "--characterSet {chars}" -- specifies the set of
 *       characters that will be used to generate the values to use for the
 *       target attributes.  It should only include ASCII characters.  Values
 *       will be generated from randomly-selected characters from this set.  If
 *       this is not provided, then a default set of lowercase alphabetic
 *       characters will be used.</LI>
 *   <LI>"-t {num}" or "--numThreads {num}" -- specifies the number of
 *       concurrent threads to use when performing the modifications.  If this
 *       is not provided, then a default of one thread will be used.</LI>
 *   <LI>"-i {sec}" or "--intervalDuration {sec}" -- specifies the length of
 *       time in seconds between lines out output.  If this is not provided,
 *       then a default interval duration of five seconds will be used.</LI>
 *   <LI>"-I {num}" or "--numIntervals {num}" -- specifies the maximum number of
 *       intervals for which to run.  If this is not provided, then it will
 *       run forever.</LI>
 *   <LI>"-r {modifies-per-second}" or "--ratePerSecond {modifies-per-second}"
 *       specifies the target number of modifies to perform per second.  It is
 *       still necessary to specify a sufficient number of threads for achieving
 *       this rate.  If this option is not provided, then the tool will run at
 *       the maximum rate for the specified number of threads.</LI>
 *   <LI>"-c" or "--csv" -- Generate output in CSV format rather than a
 *       display-friendly format.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModRate
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2709717414202815822L;



  // The argument used to indicate whether to generate output in CSV format.
  private BooleanArgument csvFormat;

  // The argument used to specify the collection interval.
  private IntegerArgument collectionInterval;

  // The argument used to specify the number of intervals.
  private IntegerArgument numIntervals;

  // The argument used to specify the number of threads.
  private IntegerArgument numThreads;

  // The target rate of modifies per second.
  private IntegerArgument ratePerSecond;

  // The argument used to specify the length of the values to generate.
  private IntegerArgument valueLength;

  // The argument used to specify the name of the attribute to modify.
  private StringArgument attribute;

  // The argument used to specify the set of characters to use when generating
  // values.
  private StringArgument characterSet;

  // The argument used to specify the DNs of the entries to modify.
  private StringArgument entryDN;



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
    final ModRate modRate = new ModRate(outStream, errStream);
    return modRate.runTool(args);
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
  public ModRate(final OutputStream outStream, final OutputStream errStream)
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
    return "modrate";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Perform repeated modifications against " +
           "an LDAP directory server.";
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
    String description = "The DN of the entry to modify.  It may be a simple " +
         "DN or a value pattern to specify a range of DN (e.g., " +
         "\"uid=user.[1-1000],ou=People,dc=example,dc=com\").  This must be " +
         "provided.";
    entryDN = new StringArgument('b', "entryDN", true, 1, "{dn}", description);
    parser.addArgument(entryDN);


    description = "The name of the attribute to modify.  Multiple attributes " +
                  "may be specified by providing this argument multiple " +
                  "times.  At least one attribute must be specified.";
    attribute = new StringArgument('A', "attribute", true, 0, "{name}",
                                   description);
    parser.addArgument(attribute);


    description = "The length in bytes to use when generating values for the " +
                  "modifications.  If this is not provided, then a default " +
                  "length of ten bytes will be used.";
    valueLength = new IntegerArgument('l', "valueLength", true, 1, "{num}",
                                      description, 1, Integer.MAX_VALUE, 10);
    parser.addArgument(valueLength);


    description = "The set of characters to use to generate the values for " +
                  "the modifications.  It should only include ASCII " +
                  "characters.  If this is not provided, then a default set " +
                  "of lowercase alphabetic characters will be used.";
    characterSet = new StringArgument('C', "characterSet", true, 1, "{chars}",
                                      description,
                                      "abcdefghijklmnopqrstuvwxyz");
    parser.addArgument(characterSet);


    description = "The number of threads to use to perform the " +
                  "modifications.  If this is not provided, a single thread " +
                  "will be used.";
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

    description = "The target number of modifies to perform per second.  It " +
                  "is still necessary to specify a sufficient number of " +
                  "threads for achieving this rate.  If this option is not " +
                  "provided, then the tool will run at the maximum rate for " +
                  "the specified number of threads.";
    ratePerSecond = new IntegerArgument('r', "ratePerSecond", false, 1,
                                        "{modifies-per-second}", description,
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
   * modifications.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Create the value pattern for the entry DN.
    final ValuePattern dnPattern;
    try
    {
      dnPattern = new ValuePattern(entryDN.getValue());
    }
    catch (ParseException pe)
    {
      err("Unable to parse the entry DN value pattern:  ", pe.getMessage());
      return ResultCode.PARAM_ERROR;
    }


    // Get the names of the attributes to modify.
    final String[] attrs = new String[attribute.getValues().size()];
    attribute.getValues().toArray(attrs);


    // Get the character set as a byte array.
    final byte[] charSet = getBytes(characterSet.getValue());


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
    final AtomicLong modCounter   = new AtomicLong(0L);
    final AtomicLong errorCounter = new AtomicLong(0L);
    final AtomicLong modDurations = new AtomicLong(0L);


    // Create the output formatters.
    final DecimalFormat longFormatter   = new DecimalFormat("0");
    final DecimalFormat doubleFormatter = new DecimalFormat("0.000");


    // Get the length of time to sleep in milliseconds.
    final long sleepTimeMillis = 1000L * collectionInterval.getValue();


    // Create a random number generator to use for seeding the per-thread
    // generators.
    final Random random = new Random();


    // Create the threads to use for the modifications.
    final ModRateThread[] threads = new ModRateThread[numThreads.getValue()];
    for (int i=0; i < threads.length; i++)
    {
      final LDAPConnection connection;
      try
      {
        connection = getConnection();
      }
      catch (LDAPException le)
      {
        err("Unable to connect to the directory server:  ",
            getExceptionMessage(le));
        return le.getResultCode();
      }

      threads[i] = new ModRateThread(i, connection, dnPattern, attrs, charSet,
           valueLength.getValue(), random.nextLong(), modCounter, modDurations,
           errorCounter, fixedRateBarrier);
    }


    // Start all of the threads.
    final long overallStartTime = System.nanoTime();
    for (final ModRateThread t : threads)
    {
      t.start();
    }


    long lastDuration  = 0L;
    long lastNumErrors = 0L;
    long lastNumMods   = 0L;
    for (int i=0; i < numIntervals.getValue(); i++)
    {
      final long startTime = System.nanoTime();
      try
      {
        Thread.sleep(sleepTimeMillis);
      } catch (Exception e) {}

      final long endTime          = System.nanoTime();
      final long intervalDuration = endTime - startTime;

      final long numMods       = modCounter.get();
      final long numErrors     = errorCounter.get();
      final long totalDuration = modDurations.get();

      final long recentNumMods = numMods - lastNumMods;
      final long recentNumErrors = numErrors - lastNumErrors;
      final long recentDuration = totalDuration - lastDuration;

      final double numSeconds = intervalDuration / 1000000000.0D;
      final double recentModRate = recentNumMods / numSeconds;
      final double recentErrorRate  = recentNumErrors / numSeconds;
      final double recentAvgDuration =
                  1.0D * recentDuration / recentNumMods / 1000000;

      final double numOverallSeconds =
           (endTime - overallStartTime) / 1000000000.0D;
      final double overallModRate = numMods / numOverallSeconds;
      final double overallAvgDuration =
           1.0D * totalDuration / numMods / 1000000;

      if (csvFormat.isPresent())
      {
        if (i == 0)
        {
          out("\"Recent Mods/Second\",",
              "\"Recent Average Modify Duration (ms)\",",
              "\"Recent Errors/Second\",",
              "\"Overall Mods/Second\",",
              "\"Overall Average Modify Duration (ms)\"");
        }

        out(longFormatter.format(recentModRate), ',',
            doubleFormatter.format(recentAvgDuration), ',',
            doubleFormatter.format(recentErrorRate), ',',
            longFormatter.format(overallModRate), ',',
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
          out("     Mods/Sec",
              "   Avg Dur ms",
              "   Errors/Sec",
              "     Mods/Sec",
              "   Avg Dur ms");
          out(" ------------",
              " ------------",
              " ------------",
              " ------------",
              " ------------");
        }

        out(formatAndAlign(recentModRate, longFormatter),
            formatAndAlign(recentAvgDuration, doubleFormatter),
            formatAndAlign(recentErrorRate,  doubleFormatter),
            formatAndAlign(overallModRate, longFormatter),
            formatAndAlign(overallAvgDuration, doubleFormatter));
      }

      lastNumMods   = numMods;
      lastNumErrors = numErrors;
      lastDuration  = totalDuration;
    }


    // Stop all of the threads.
    ResultCode resultCode = ResultCode.SUCCESS;
    for (final ModRateThread t : threads)
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
      "--entryDN", "uid=user.[1-1000000],ou=People,dc=example,dc=com",
      "--attribute", "description",
      "--valueLength", "12",
      "--numThreads", "10"
    };
    final String description =
         "Test modify performance by randomly selecting entries across a set " +
         "of one million users located below 'ou=People,dc=example,dc=com' " +
         "with ten concurrent threads and replacing the values for the " +
         "description attribute with a string of 12 randomly-selected " +
         "lowercase alphabetic characters.";
    examples.put(args, description);

    return examples;
  }
}
