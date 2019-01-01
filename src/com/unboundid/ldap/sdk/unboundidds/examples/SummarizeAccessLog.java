/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;
import javax.crypto.BadPaddingException;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.logs.AbandonRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogReader;
import com.unboundid.ldap.sdk.unboundidds.logs.AddResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.BindResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.CompareResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.ConnectAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.DeleteResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.DisconnectAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.ExtendedRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.ExtendedResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.ModifyDNResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.ModifyResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.OperationAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.SearchRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.SearchResultAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.logs.UnbindRequestAccessLogMessage;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ReverseComparator;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;



/**
 * This class provides a tool that may be used to read and summarize the
 * contents of one or more access log files from Ping Identity, UnboundID and
 * Nokia/Alcatel-Lucent 8661 server products.
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
 * Information that will be reported includes:
 * <UL>
 *   <LI>The total length of time covered by the log files.</LI>
 *   <LI>The number of connections established and disconnected, the addresses
 *       of the most commonly-connecting clients, and the average rate of
 *       connects and disconnects per second.</LI>
 *   <LI>The number of operations processed, overall and by operation type,
 *       and the average rate of operations per second.</LI>
 *   <LI>The average duration for operations processed, overall and by operation
 *       type.</LI>
 *   <LI>A breakdown of operation processing times into a number of predefined
 *       categories (less than 1ms, between 1ms and 2ms, between 2ms and 3ms,
 *       between 3ms and 5ms, between 5ms and 10ms, between 10ms and 20ms,
 *       between 20ms and 30ms, between 30ms and 50ms, between 50ms and 100ms,
 *       between 100ms and 1000ms, and over 1000ms).</LI>
 *   <LI>A breakdown of the most common result codes for each type of operation
 *       and their relative frequencies.</LI>
 *   <LI>The most common types of extended requests processed and their
 *       relative frequencies.</LI>
 *   <LI>The number of unindexed search operations processed.</LI>
 *   <LI>A breakdown of the relative frequencies for each type of search
 *       scope.</LI>
 *   <LI>The most common types of search filters used for search
 *       operations and their relative frequencies.</LI>
 * </UL>
 * It is designed to work with access log files using either the default log
 * format with separate request and response messages, as well as log files
 * in which the request and response details have been combined on the same
 * line.  The log files to be processed should be provided as command-line
 * arguments.
 * <BR><BR>
 * The APIs demonstrated by this example include:
 * <UL>
 *   <LI>Access log parsing (from the
 *       {@code com.unboundid.ldap.sdk.unboundidds.logs} package)</LI>
 *   <LI>Argument parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SummarizeAccessLog
       extends CommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7189168366509887130L;



  // Variables used for accessing argument information.
  private ArgumentParser  argumentParser;

  // An argument which may be used to indicate that the log files are
  // compressed.
  private BooleanArgument isCompressed;

  // An argument used to specify the encryption passphrase.
  private FileArgument    encryptionPassphraseFile;

  // The decimal format that will be used for this class.
  private final DecimalFormat decimalFormat;

  // The total duration for log content, in milliseconds.
  private long logDurationMillis;

  // The total processing time for each type of operation.
  private double addProcessingDuration;
  private double bindProcessingDuration;
  private double compareProcessingDuration;
  private double deleteProcessingDuration;
  private double extendedProcessingDuration;
  private double modifyProcessingDuration;
  private double modifyDNProcessingDuration;
  private double searchProcessingDuration;

  // A variable used for counting the number of messages of each type.
  private long numAbandons;
  private long numAdds;
  private long numBinds;
  private long numCompares;
  private long numConnects;
  private long numDeletes;
  private long numDisconnects;
  private long numExtended;
  private long numModifies;
  private long numModifyDNs;
  private long numNonBaseSearches;
  private long numSearches;
  private long numUnbinds;

  // The number of operations of each type that accessed uncached data.
  private long numUncachedAdds;
  private long numUncachedBinds;
  private long numUncachedCompares;
  private long numUncachedDeletes;
  private long numUncachedExtended;
  private long numUncachedModifies;
  private long numUncachedModifyDNs;
  private long numUncachedSearches;

  // The number of unindexed searches processed within the server.
  private long numUnindexedAttempts;
  private long numUnindexedFailed;
  private long numUnindexedSuccessful;

  // Variables used for maintaining counts for common types of information.
  private final HashMap<Long,AtomicLong> searchEntryCounts;
  private final HashMap<ResultCode,AtomicLong> addResultCodes;
  private final HashMap<ResultCode,AtomicLong> bindResultCodes;
  private final HashMap<ResultCode,AtomicLong> compareResultCodes;
  private final HashMap<ResultCode,AtomicLong> deleteResultCodes;
  private final HashMap<ResultCode,AtomicLong> extendedResultCodes;
  private final HashMap<ResultCode,AtomicLong> modifyResultCodes;
  private final HashMap<ResultCode,AtomicLong> modifyDNResultCodes;
  private final HashMap<ResultCode,AtomicLong> searchResultCodes;
  private final HashMap<SearchScope,AtomicLong> searchScopes;
  private final HashMap<String,AtomicLong> clientAddresses;
  private final HashMap<String,AtomicLong> clientConnectionPolicies;
  private final HashMap<String,AtomicLong> disconnectReasons;
  private final HashMap<String,AtomicLong> extendedOperations;
  private final HashMap<String,AtomicLong> filterTypes;
  private final HashSet<String> processedRequests;
  private final LinkedHashMap<Long,AtomicLong> addProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> bindProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> compareProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> deleteProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> extendedProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> modifyProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> modifyDNProcessingTimes;
  private final LinkedHashMap<Long,AtomicLong> searchProcessingTimes;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
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
   * Parse the provided command line arguments and perform the appropriate
   * processing.
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
    final SummarizeAccessLog summarizer =
         new SummarizeAccessLog(outStream, errStream);
    return summarizer.runTool(args);
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
  public SummarizeAccessLog(final OutputStream outStream,
                            final OutputStream errStream)
  {
    super(outStream, errStream);

    decimalFormat = new DecimalFormat("0.000");

    logDurationMillis = 0L;

    addProcessingDuration      = 0.0;
    bindProcessingDuration     = 0.0;
    compareProcessingDuration  = 0.0;
    deleteProcessingDuration   = 0.0;
    extendedProcessingDuration = 0.0;
    modifyProcessingDuration   = 0.0;
    modifyDNProcessingDuration = 0.0;
    searchProcessingDuration   = 0.0;

    numAbandons        = 0L;
    numAdds            = 0L;
    numBinds           = 0L;
    numCompares        = 0L;
    numConnects        = 0L;
    numDeletes         = 0L;
    numDisconnects     = 0L;
    numExtended        = 0L;
    numModifies        = 0L;
    numModifyDNs       = 0L;
    numNonBaseSearches = 0L;
    numSearches        = 0L;
    numUnbinds         = 0L;

    numUncachedAdds      = 0L;
    numUncachedBinds     = 0L;
    numUncachedCompares  = 0L;
    numUncachedDeletes   = 0L;
    numUncachedExtended  = 0L;
    numUncachedModifies  = 0L;
    numUncachedModifyDNs = 0L;
    numUncachedSearches  = 0L;

    searchEntryCounts = new HashMap<>(StaticUtils.computeMapCapacity(10));
    addResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    bindResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    compareResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    deleteResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    extendedResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    modifyResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    modifyDNResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    searchResultCodes = new HashMap<>(StaticUtils.computeMapCapacity(10));
    searchScopes = new HashMap<>(StaticUtils.computeMapCapacity(4));
    clientAddresses = new HashMap<>(StaticUtils.computeMapCapacity(100));
    clientConnectionPolicies =
         new HashMap<>(StaticUtils.computeMapCapacity(100));
    disconnectReasons = new HashMap<>(StaticUtils.computeMapCapacity(100));
    extendedOperations = new HashMap<>(StaticUtils.computeMapCapacity(10));
    filterTypes = new HashMap<>(StaticUtils.computeMapCapacity(100));
    processedRequests = new HashSet<>(StaticUtils.computeMapCapacity(100));
    addProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    bindProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    compareProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    deleteProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    extendedProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    modifyProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    modifyDNProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));
    searchProcessingTimes =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(11));

    populateProcessingTimeMap(addProcessingTimes);
    populateProcessingTimeMap(bindProcessingTimes);
    populateProcessingTimeMap(compareProcessingTimes);
    populateProcessingTimeMap(deleteProcessingTimes);
    populateProcessingTimeMap(extendedProcessingTimes);
    populateProcessingTimeMap(modifyProcessingTimes);
    populateProcessingTimeMap(modifyDNProcessingTimes);
    populateProcessingTimeMap(searchProcessingTimes);
  }



  /**
   * Retrieves the name for this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  public String getToolName()
  {
    return "summarize-access-log";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Examine one or more access log files from Ping Identity, " +
         "UnboundID, or Nokia/Alcatel-Lucent 8661 server products to display " +
         "a number of metrics about operations processed within the server.";
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
   * Retrieves the minimum number of unnamed trailing arguments that are
   * required.
   *
   * @return  One, to indicate that at least one trailing argument (representing
   *          the path to an access log file) must be provided.
   */
  @Override()
  public int getMinTrailingArguments()
  {
    return 1;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that may be
   * provided for this tool.
   *
   * @return  The maximum number of unnamed trailing arguments that may be
   *          provided for this tool.
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return -1;
  }



  /**
   * Retrieves a placeholder string that should be used for trailing arguments
   * in the usage information for this tool.
   *
   * @return  A placeholder string that should be used for trailing arguments in
   *          the usage information for this tool.
   */
  @Override()
  public String getTrailingArgumentsPlaceholder()
  {
    return "{path}";
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
  public void addToolArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    // We need to save a reference to the argument parser so that we can get
    // the trailing arguments later.
    argumentParser = parser;

    // Add an argument that makes it possible to read a compressed log file.
    // Note that this argument is no longer needed for dealing with compressed
    // files, since the tool will automatically detect whether a file is
    // compressed.  However, the argument is still provided for the purpose of
    // backward compatibility.
    String description = "Indicates that the log file is compressed.";
    isCompressed = new BooleanArgument('c', "isCompressed", description);
    isCompressed.addLongIdentifier("is-compressed", true);
    isCompressed.addLongIdentifier("compressed", true);
    isCompressed.setHidden(true);
    parser.addArgument(isCompressed);


    // Add an argument that indicates that the tool should read the encryption
    // passphrase from a file.
    description = "Indicates that the log file is encrypted and that the " +
         "encryption passphrase is contained in the specified file.  If " +
         "the log data is encrypted and this argument is not provided, then " +
         "the tool will interactively prompt for the encryption passphrase.";
    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null, description, true, true,
         true, false);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    parser.addArgument(encryptionPassphraseFile);
  }



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and immediately
   * before the {@link CommandLineTool#doToolProcessing} method is invoked.
   *
   * @throws  ArgumentException  If there was a problem with the command-line
   *                             arguments provided to this program.
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // Make sure that at least one access log file path was provided.
    final List<String> trailingArguments =
         argumentParser.getTrailingArguments();
    if ((trailingArguments == null) || trailingArguments.isEmpty())
    {
      throw new ArgumentException("No access log file paths were provided.");
    }
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    String encryptionPassphrase = null;
    if (encryptionPassphraseFile.isPresent())
    {
      try
      {
        encryptionPassphrase = ToolUtils.readEncryptionPassphraseFromFile(
             encryptionPassphraseFile.getValue());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        err(e.getMessage());
        return e.getResultCode();
      }
    }


    long logLines = 0L;
    for (final String path : argumentParser.getTrailingArguments())
    {
      final File f = new File(path);
      out("Examining access log ", f.getAbsolutePath());
      AccessLogReader reader = null;
      InputStream inputStream = null;
      try
      {
        inputStream = new FileInputStream(f);

        final ObjectPair<InputStream,String> p =
             ToolUtils.getPossiblyPassphraseEncryptedInputStream(inputStream,
                  encryptionPassphrase,
                  (! encryptionPassphraseFile.isPresent()),
                  "Log file '" + path + "' is encrypted.  Please enter the " +
                       "encryption passphrase:",
                  "ERROR:  The provided passphrase was incorrect.",
                  getOut(), getErr());
        inputStream = p.getFirst();
        if ((p.getSecond() != null) && (encryptionPassphrase == null))
        {
          encryptionPassphrase = p.getSecond();
        }

        if (isCompressed.isPresent())
        {
          inputStream = new GZIPInputStream(inputStream);
        }
        else
        {
          inputStream =
               ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);
        }

        reader = new AccessLogReader(new InputStreamReader(inputStream));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err("Unable to open access log file ", f.getAbsolutePath(), ":  ",
            StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
      finally
      {
        if ((reader == null) && (inputStream != null))
        {
          try
          {
            inputStream.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }

      long startTime = 0L;
      long stopTime  = 0L;

      while (true)
      {
        final AccessLogMessage msg;
        try
        {
          msg = reader.read();
        }
        catch (final IOException ioe)
        {
          Debug.debugException(ioe);
          err("Error reading from access log file ", f.getAbsolutePath(),
              ":  ", StaticUtils.getExceptionMessage(ioe));

          if ((ioe.getCause() != null) &&
               (ioe.getCause() instanceof BadPaddingException))
          {
            err("This error is likely because the log is encrypted and the " +
                 "server still has the log file open.  It is recommended " +
                 "that you only try to examine encrypted logs after they " +
                 "have been rotated.  You can use the rotate-log tool to " +
                 "force a rotation at any time.  Attempting to proceed with " +
                 "just the data that was successfully read.");
            break;
          }
          else
          {
            return ResultCode.LOCAL_ERROR;
          }
        }
        catch (final LogException le)
        {
          Debug.debugException(le);
          err("Encountered an error while attempting to parse a line in" +
              "access log file ", f.getAbsolutePath(), ":  ",
              StaticUtils.getExceptionMessage(le));
          continue;
        }

        if (msg == null)
        {
          break;
        }

        logLines++;
        stopTime = msg.getTimestamp().getTime();
        if (startTime == 0L)
        {
          startTime = stopTime;
        }

        switch (msg.getMessageType())
        {
          case CONNECT:
            processConnect((ConnectAccessLogMessage) msg);
            break;
          case DISCONNECT:
            processDisconnect((DisconnectAccessLogMessage) msg);
            break;
          case REQUEST:
            switch (((OperationAccessLogMessage) msg).getOperationType())
            {
              case ABANDON:
                processAbandonRequest((AbandonRequestAccessLogMessage) msg);
                break;
              case EXTENDED:
                processExtendedRequest((ExtendedRequestAccessLogMessage) msg);
                break;
              case SEARCH:
                processSearchRequest((SearchRequestAccessLogMessage) msg);
                break;
              case UNBIND:
                processUnbindRequest((UnbindRequestAccessLogMessage) msg);
                break;
            }
            break;
          case RESULT:
            switch (((OperationAccessLogMessage) msg).getOperationType())
            {
              case ADD:
                processAddResult((AddResultAccessLogMessage) msg);
                break;
              case BIND:
                processBindResult((BindResultAccessLogMessage) msg);
                break;
              case COMPARE:
                processCompareResult((CompareResultAccessLogMessage) msg);
                break;
              case DELETE:
                processDeleteResult((DeleteResultAccessLogMessage) msg);
                break;
              case EXTENDED:
                processExtendedResult((ExtendedResultAccessLogMessage) msg);
                break;
              case MODIFY:
                processModifyResult((ModifyResultAccessLogMessage) msg);
                break;
              case MODDN:
                processModifyDNResult((ModifyDNResultAccessLogMessage) msg);
                break;
              case SEARCH:
                processSearchResult((SearchResultAccessLogMessage) msg);
                break;
            }
            break;

          case ASSURANCE_COMPLETE:
          case CLIENT_CERTIFICATE:
          case ENTRY_REBALANCING_REQUEST:
          case ENTRY_REBALANCING_RESULT:
          case FORWARD:
          case FORWARD_FAILED:
          case ENTRY:
          case REFERENCE:
          default:
            // Nothing needs to be done for these message types.
        }
      }

      try
      {
        reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      logDurationMillis += (stopTime - startTime);
    }


    final int numFiles = argumentParser.getTrailingArguments().size();
    out();
    out("Examined ", logLines, " lines in ", numFiles,
        ((numFiles == 1) ? " file" : " files"),
        " covering a total duration of ",
        StaticUtils.millisToHumanReadableDuration(logDurationMillis));
    if (logLines == 0)
    {
      return ResultCode.SUCCESS;
    }

    out();

    final double logDurationSeconds   = logDurationMillis / 1000.0;
    final double connectsPerSecond    = numConnects / logDurationSeconds;
    final double disconnectsPerSecond = numDisconnects / logDurationSeconds;

    out("Total connections established:  ", numConnects, " (",
        decimalFormat.format(connectsPerSecond), "/second)");
    out("Total disconnects:  ", numDisconnects, " (",
        decimalFormat.format(disconnectsPerSecond), "/second)");

    if (! clientAddresses.isEmpty())
    {
      out();
      final List<ObjectPair<String,Long>> connectCounts =
           getMostCommonElements(clientAddresses, 20);
      out("Most common client addresses:");
      for (final ObjectPair<String,Long> p : connectCounts)
      {
        final long count = p.getSecond();
        final double percent = 100.0 * count / numConnects;

        out(p.getFirst(), ":  ", count, " (", decimalFormat.format(percent),
            ")");
      }
    }

    if (! clientConnectionPolicies.isEmpty())
    {
      long totalCCPs = 0;
      for (final AtomicLong l : clientConnectionPolicies.values())
      {
        totalCCPs += l.get();
      }

      final List<ObjectPair<String,Long>> reasonCounts =
           getMostCommonElements(clientConnectionPolicies, 20);

      out();
      out("Most common client connection policies:");
      for (final ObjectPair<String,Long> p : reasonCounts)
      {
        final long count = p.getSecond();
        final double percent = 100.0 * count / totalCCPs;
        out(p.getFirst(), ":  ", p.getSecond(), " (",
             decimalFormat.format(percent), "%)");
      }
    }

    if (! disconnectReasons.isEmpty())
    {
      final List<ObjectPair<String,Long>> reasonCounts =
           getMostCommonElements(disconnectReasons, 20);

      out();
      out("Most common disconnect reasons:");
      for (final ObjectPair<String,Long> p : reasonCounts)
      {
        final long count = p.getSecond();
        final double percent = 100.0 * count / numDisconnects;
        out(p.getFirst(), ":  ", p.getSecond(), " (",
             decimalFormat.format(percent), "%)");
      }
    }

    final long totalOps = numAbandons + numAdds + numBinds + numCompares +
         numDeletes + numExtended + numModifies + numModifyDNs + numSearches +
         numUnbinds;
    if (totalOps > 0)
    {
      final double percentAbandon  = 100.0 * numAbandons / totalOps;
      final double percentAdd      = 100.0 * numAdds / totalOps;
      final double percentBind     = 100.0 * numBinds / totalOps;
      final double percentCompare  = 100.0 * numCompares / totalOps;
      final double percentDelete   = 100.0 * numDeletes / totalOps;
      final double percentExtended = 100.0 * numExtended / totalOps;
      final double percentModify   = 100.0 * numModifies / totalOps;
      final double percentModifyDN = 100.0 * numModifyDNs / totalOps;
      final double percentSearch   = 100.0 * numSearches / totalOps;
      final double percentUnbind   = 100.0 * numUnbinds / totalOps;

      final double abandonsPerSecond  = numAbandons / logDurationSeconds;
      final double addsPerSecond      = numAdds / logDurationSeconds;
      final double bindsPerSecond     = numBinds / logDurationSeconds;
      final double comparesPerSecond  = numCompares / logDurationSeconds;
      final double deletesPerSecond   = numDeletes / logDurationSeconds;
      final double extendedPerSecond  = numExtended / logDurationSeconds;
      final double modifiesPerSecond  = numModifies / logDurationSeconds;
      final double modifyDNsPerSecond = numModifyDNs / logDurationSeconds;
      final double searchesPerSecond  = numSearches / logDurationSeconds;
      final double unbindsPerSecond   = numUnbinds / logDurationSeconds;

      out();
      out("Total operations examined:  ", totalOps);
      out("Abandon operations examined:  ", numAbandons, " (",
          decimalFormat.format(percentAbandon), "%, ",
          decimalFormat.format(abandonsPerSecond), "/second)");
      out("Add operations examined:  ", numAdds, " (",
          decimalFormat.format(percentAdd), "%, ",
          decimalFormat.format(addsPerSecond), "/second)");
      out("Bind operations examined:  ", numBinds, " (",
          decimalFormat.format(percentBind), "%, ",
          decimalFormat.format(bindsPerSecond), "/second)");
      out("Compare operations examined:  ", numCompares, " (",
          decimalFormat.format(percentCompare), "%, ",
          decimalFormat.format(comparesPerSecond), "/second)");
      out("Delete operations examined:  ", numDeletes, " (",
          decimalFormat.format(percentDelete), "%, ",
          decimalFormat.format(deletesPerSecond), "/second)");
      out("Extended operations examined:  ", numExtended, " (",
          decimalFormat.format(percentExtended), "%, ",
          decimalFormat.format(extendedPerSecond), "/second)");
      out("Modify operations examined:  ", numModifies, " (",
          decimalFormat.format(percentModify), "%, ",
          decimalFormat.format(modifiesPerSecond), "/second)");
      out("Modify DN operations examined:  ", numModifyDNs, " (",
          decimalFormat.format(percentModifyDN), "%, ",
          decimalFormat.format(modifyDNsPerSecond), "/second)");
      out("Search operations examined:  ", numSearches, " (",
          decimalFormat.format(percentSearch), "%, ",
          decimalFormat.format(searchesPerSecond), "/second)");
      out("Unbind operations examined:  ", numUnbinds, " (",
          decimalFormat.format(percentUnbind), "%, ",
          decimalFormat.format(unbindsPerSecond), "/second)");

      final double totalProcessingDuration = addProcessingDuration +
           bindProcessingDuration + compareProcessingDuration +
           deleteProcessingDuration + extendedProcessingDuration +
           modifyProcessingDuration + modifyDNProcessingDuration +
           searchProcessingDuration;

      out();
      out("Average operation processing duration:  ",
          decimalFormat.format(totalProcessingDuration / totalOps), "ms");

      if (numAdds > 0)
      {
        out("Average add operation processing duration:  ",
            decimalFormat.format(addProcessingDuration / numAdds), "ms");
      }

      if (numBinds > 0)
      {
        out("Average bind operation processing duration:  ",
            decimalFormat.format(bindProcessingDuration / numBinds), "ms");
      }

      if (numCompares > 0)
      {
        out("Average compare operation processing duration:  ",
            decimalFormat.format(compareProcessingDuration / numCompares),
            "ms");
      }

      if (numDeletes > 0)
      {
        out("Average delete operation processing duration:  ",
            decimalFormat.format(deleteProcessingDuration / numDeletes), "ms");
      }

      if (numExtended > 0)
      {
        out("Average extended operation processing duration:  ",
            decimalFormat.format(extendedProcessingDuration / numExtended),
            "ms");
      }

      if (numModifies > 0)
      {
        out("Average modify operation processing duration:  ",
            decimalFormat.format(modifyProcessingDuration / numModifies), "ms");
      }

      if (numModifyDNs > 0)
      {
        out("Average modify DN operation processing duration:  ",
            decimalFormat.format(modifyDNProcessingDuration / numModifyDNs),
            "ms");
      }

      if (numSearches > 0)
      {
        out("Average search operation processing duration:  ",
            decimalFormat.format(searchProcessingDuration / numSearches), "ms");
      }

      printProcessingTimeHistogram("add", numAdds, addProcessingTimes);
      printProcessingTimeHistogram("bind", numBinds, bindProcessingTimes);
      printProcessingTimeHistogram("compare", numCompares,
                                   compareProcessingTimes);
      printProcessingTimeHistogram("delete", numDeletes, deleteProcessingTimes);
      printProcessingTimeHistogram("extended", numExtended,
                                   extendedProcessingTimes);
      printProcessingTimeHistogram("modify", numModifies,
                                   modifyProcessingTimes);
      printProcessingTimeHistogram("modify DN", numModifyDNs,
                                 modifyDNProcessingTimes);
      printProcessingTimeHistogram("search", numSearches,
                                   searchProcessingTimes);

      if (! addResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(addResultCodes, 20);

        out();
        out("Most common add operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numAdds;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! bindResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(bindResultCodes, 20);

        out();
        out("Most common bind operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numBinds;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! compareResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(compareResultCodes, 20);

        out();
        out("Most common compare operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numCompares;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! deleteResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(deleteResultCodes, 20);

        out();
        out("Most common delete operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numDeletes;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! extendedResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(extendedResultCodes, 20);

        out();
        out("Most common extended operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numExtended;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! modifyResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(modifyResultCodes, 20);

        out();
        out("Most common modify operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numModifies;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! modifyDNResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(modifyDNResultCodes, 20);

        out();
        out("Most common modify DN operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numModifyDNs;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! searchResultCodes.isEmpty())
      {
        final List<ObjectPair<ResultCode,Long>> rcCounts =
             getMostCommonElements(searchResultCodes, 20);

        out();
        out("Most common search operation result codes:");
        for (final ObjectPair<ResultCode,Long> p : rcCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numSearches;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! extendedOperations.isEmpty())
      {
        final List<ObjectPair<String,Long>> extOpCounts =
             getMostCommonElements(extendedOperations, 20);

        out();
        out("Most common extended operation types:");
        for (final ObjectPair<String,Long> p : extOpCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numExtended;
          out(p.getFirst(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      out();
      out("Number of unindexed search attempts:  ", numUnindexedAttempts);
      out("Number of successfully-completed unindexed searches:  ",
           numUnindexedSuccessful);
      out("Number of failed unindexed searches:  ", numUnindexedFailed);

      if (! searchScopes.isEmpty())
      {
        final List<ObjectPair<SearchScope,Long>> scopeCounts =
             getMostCommonElements(searchScopes, 20);

        out();
        out("Most common search scopes:");
        for (final ObjectPair<SearchScope,Long> p : scopeCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numSearches;
          out(p.getFirst().getName(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! searchEntryCounts.isEmpty())
      {
        final List<ObjectPair<Long,Long>> entryCounts =
             getMostCommonElements(searchEntryCounts, 20);

        out();
        out("Most common search entry counts:");
        for (final ObjectPair<Long,Long> p : entryCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numSearches;
          out(p.getFirst(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }

      if (! filterTypes.isEmpty())
      {
        final List<ObjectPair<String,Long>> filterCounts =
             getMostCommonElements(filterTypes, 20);

        out();
        out("Most common generic filters for searches with a non-base scope:");
        for (final ObjectPair<String,Long> p : filterCounts)
        {
          final long count = p.getSecond();
          final double percent = 100.0 * count / numNonBaseSearches;
          out(p.getFirst(), ":  ", p.getSecond(), " (",
              decimalFormat.format(percent), "%)");
        }
      }
    }

    final long totalUncached = numUncachedAdds + numUncachedBinds +
         numUncachedCompares + numUncachedDeletes + numUncachedExtended +
         numUncachedModifies + numUncachedModifyDNs + numUncachedSearches;
    if (totalUncached > 0L)
    {
      out();
      out("Operations accessing uncached data:");
      printUncached("Add", numUncachedAdds, numAdds);
      printUncached("Bind", numUncachedBinds, numBinds);
      printUncached("Compare", numUncachedCompares, numCompares);
      printUncached("Delete", numUncachedDeletes, numDeletes);
      printUncached("Extended", numUncachedExtended, numExtended);
      printUncached("Modify", numUncachedModifies, numModifies);
      printUncached("Modify DN", numUncachedModifyDNs, numModifyDNs);
      printUncached("Search", numUncachedSearches, numSearches);
    }


    return ResultCode.SUCCESS;
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
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "/ds/logs/access"
    };
    final String description =
         "Analyze the contents of the /ds/logs/access access log file.";
    examples.put(args, description);

    return examples;
  }



  /**
   * Populates the provided processing time map with an initial set of values.
   *
   * @param  m  The processing time map to be populated.
   */
  private static void populateProcessingTimeMap(
                           final HashMap<Long,AtomicLong> m)
  {
    m.put(1L, new AtomicLong(0L));
    m.put(2L, new AtomicLong(0L));
    m.put(3L, new AtomicLong(0L));
    m.put(5L, new AtomicLong(0L));
    m.put(10L, new AtomicLong(0L));
    m.put(20L, new AtomicLong(0L));
    m.put(30L, new AtomicLong(0L));
    m.put(50L, new AtomicLong(0L));
    m.put(100L, new AtomicLong(0L));
    m.put(1000L, new AtomicLong(0L));
    m.put(Long.MAX_VALUE, new AtomicLong(0L));
  }



  /**
   * Performs any necessary processing for a connect message.
   *
   * @param  m  The log message to be processed.
   */
  private void processConnect(final ConnectAccessLogMessage m)
  {
    numConnects++;

    final String clientAddr = m.getSourceAddress();
    if (clientAddr != null)
    {
      AtomicLong count = clientAddresses.get(clientAddr);
      if (count == null)
      {
        count = new AtomicLong(0L);
        clientAddresses.put(clientAddr, count);
      }
      count.incrementAndGet();
    }

    final String ccp = m.getClientConnectionPolicy();
    if (ccp != null)
    {
      AtomicLong l = clientConnectionPolicies.get(ccp);
      if (l == null)
      {
        l = new AtomicLong(0L);
        clientConnectionPolicies.put(ccp, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for a disconnect message.
   *
   * @param  m  The log message to be processed.
   */
  private void processDisconnect(final DisconnectAccessLogMessage m)
  {
    numDisconnects++;

    final String reason = m.getDisconnectReason();
    if (reason != null)
    {
      AtomicLong l = disconnectReasons.get(reason);
      if (l == null)
      {
        l = new AtomicLong(0L);
        disconnectReasons.put(reason, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for an abandon request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processAbandonRequest(final AbandonRequestAccessLogMessage m)
  {
    numAbandons++;
  }



  /**
   * Performs any necessary processing for an extended request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedRequest(final ExtendedRequestAccessLogMessage m)
  {
    processedRequests.add(m.getConnectionID() + "-" + m.getOperationID());
    processExtendedRequestInternal(m);
  }



  /**
   * Performs the internal processing for an extended request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedRequestInternal(
                    final ExtendedRequestAccessLogMessage m)
  {
    final String oid = m.getRequestOID();
    if (oid != null)
    {
      AtomicLong l = extendedOperations.get(oid);
      if (l == null)
      {
        l  = new AtomicLong(0L);
        extendedOperations.put(oid, l);
      }
      l.incrementAndGet();
    }
  }



  /**
   * Performs any necessary processing for a search request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchRequest(final SearchRequestAccessLogMessage m)
  {
    processedRequests.add(m.getConnectionID() + "-" + m.getOperationID());
    processSearchRequestInternal(m);
  }



  /**
   * Performs any necessary processing for a search request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchRequestInternal(
                    final SearchRequestAccessLogMessage m)
  {
    final SearchScope scope = m.getScope();
    if (scope != null)
    {
      if (scope != SearchScope.BASE)
      {
        numNonBaseSearches++;
      }

      AtomicLong scopeCount = searchScopes.get(scope);
      if (scopeCount == null)
      {
        scopeCount = new AtomicLong(0L);
        searchScopes.put(scope, scopeCount);
      }
      scopeCount.incrementAndGet();

      if (! scope.equals(SearchScope.BASE))
      {
        final Filter filter = m.getParsedFilter();
        if (filter != null)
        {
          final String genericString = new GenericFilter(filter).toString();
          AtomicLong filterCount = filterTypes.get(genericString);
          if (filterCount == null)
          {
            filterCount = new AtomicLong(0L);
            filterTypes.put(genericString, filterCount);
          }
          filterCount.incrementAndGet();
        }
      }
    }
  }



  /**
   * Performs any necessary processing for an unbind request message.
   *
   * @param  m  The log message to be processed.
   */
  private void processUnbindRequest(final UnbindRequestAccessLogMessage m)
  {
    numUnbinds++;
  }



  /**
   * Performs any necessary processing for an add result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processAddResult(final AddResultAccessLogMessage m)
  {
    numAdds++;

    updateResultCodeCount(m.getResultCode(), addResultCodes);
    addProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), addProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedAdds++;
    }
  }



  /**
   * Performs any necessary processing for a bind result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processBindResult(final BindResultAccessLogMessage m)
  {
    numBinds++;

    updateResultCodeCount(m.getResultCode(), bindResultCodes);
    bindProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), bindProcessingTimes);

    final String ccp = m.getClientConnectionPolicy();
    if (ccp != null)
    {
      AtomicLong l = clientConnectionPolicies.get(ccp);
      if (l == null)
      {
        l = new AtomicLong(0L);
        clientConnectionPolicies.put(ccp, l);
      }
      l.incrementAndGet();
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedBinds++;
    }
  }



  /**
   * Performs any necessary processing for a compare result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processCompareResult(final CompareResultAccessLogMessage m)
  {
    numCompares++;

    updateResultCodeCount(m.getResultCode(), compareResultCodes);
    compareProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), compareProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedCompares++;
    }
  }



  /**
   * Performs any necessary processing for a delete result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processDeleteResult(final DeleteResultAccessLogMessage m)
  {
    numDeletes++;

    updateResultCodeCount(m.getResultCode(), deleteResultCodes);
    deleteProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), deleteProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedDeletes++;
    }
  }



  /**
   * Performs any necessary processing for an extended result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processExtendedResult(final ExtendedResultAccessLogMessage m)
  {
    numExtended++;

    final String id = m.getConnectionID() + "-" + m.getOperationID();
    if (!processedRequests.remove(id))
    {
      processExtendedRequestInternal(m);
    }

    updateResultCodeCount(m.getResultCode(), extendedResultCodes);
    extendedProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), extendedProcessingTimes);

    final String ccp = m.getClientConnectionPolicy();
    if (ccp != null)
    {
      AtomicLong l = clientConnectionPolicies.get(ccp);
      if (l == null)
      {
        l = new AtomicLong(0L);
        clientConnectionPolicies.put(ccp, l);
      }
      l.incrementAndGet();
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedExtended++;
    }
  }



  /**
   * Performs any necessary processing for a modify result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processModifyResult(final ModifyResultAccessLogMessage m)
  {
    numModifies++;

    updateResultCodeCount(m.getResultCode(), modifyResultCodes);
    modifyProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), modifyProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedModifies++;
    }
  }



  /**
   * Performs any necessary processing for a modify DN result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processModifyDNResult(final ModifyDNResultAccessLogMessage m)
  {
    numModifyDNs++;

    updateResultCodeCount(m.getResultCode(), modifyDNResultCodes);
    modifyDNProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), modifyDNProcessingTimes);

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedModifyDNs++;
    }
  }



  /**
   * Performs any necessary processing for a search result message.
   *
   * @param  m  The log message to be processed.
   */
  private void processSearchResult(final SearchResultAccessLogMessage m)
  {
    numSearches++;

    final String id = m.getConnectionID() + "-" + m.getOperationID();
    if (!processedRequests.remove(id))
    {
      processSearchRequestInternal(m);
    }

    final ResultCode resultCode = m.getResultCode();
    updateResultCodeCount(resultCode, searchResultCodes);
    searchProcessingDuration +=
         doubleValue(m.getProcessingTimeMillis(), searchProcessingTimes);

    final Long entryCount = m.getEntriesReturned();
    if (entryCount != null)
    {
      AtomicLong l = searchEntryCounts.get(entryCount);
      if (l == null)
      {
        l = new AtomicLong(0L);
        searchEntryCounts.put(entryCount, l);
      }
      l.incrementAndGet();
    }

    final Boolean isUnindexed = m.isUnindexed();
    if ((isUnindexed != null) && isUnindexed)
    {
      numUnindexedAttempts++;
      if (resultCode == ResultCode.SUCCESS)
      {
        numUnindexedSuccessful++;
      }
      else
      {
        numUnindexedFailed++;
      }
    }

    final Boolean uncachedDataAccessed = m.getUncachedDataAccessed();
    if ((uncachedDataAccessed != null) && uncachedDataAccessed)
    {
      numUncachedSearches++;
    }
  }



  /**
   * Updates the count for the provided result code in the given map.
   *
   * @param  rc  The result code for which to update the count.
   * @param  m   The map used to hold counts by result code.
   */
  private static void updateResultCodeCount(final ResultCode rc,
                           final HashMap<ResultCode,AtomicLong> m)
  {
    if (rc == null)
    {
      return;
    }

    AtomicLong l = m.get(rc);
    if (l == null)
    {
      l = new AtomicLong(0L);
      m.put(rc, l);
    }
    l.incrementAndGet();
  }



  /**
   * Retrieves the double value for the provided {@code Double} object.
   *
   * @param  d  The {@code Double} object for which to retrieve the value.
   * @param  m  The processing time histogram map to be updated.
   *
   * @return  The double value of the provided {@code Double} object if it was
   *          non-{@code null}, or 0.0 if it was {@code null}.
   */
  private static double doubleValue(final Double d,
                                    final HashMap<Long,AtomicLong> m)
  {
    if (d == null)
    {
      return 0.0;
    }
    else
    {
      for (final Map.Entry<Long,AtomicLong> e : m.entrySet())
      {
        if (d <= e.getKey())
        {
          e.getValue().incrementAndGet();
          break;
        }
      }

      return d;
    }
  }



  /**
   * Retrieves a list of the most frequently-occurring elements in the
   * provided map, paired with the number of times each value occurred.
   *
   * @param  <K>  The type of object used as the key for the provided map.
   * @param  m    The map to be examined.  It is expected that the values of the
   *              map will be the count of occurrences for the keys.
   * @param  n    The number of elements to return.
   *
   * @return  A list of the most frequently-occurring elements in the provided
   *          map.
   */
  private static <K> List<ObjectPair<K,Long>> getMostCommonElements(
                                                   final Map<K,AtomicLong> m,
                                                   final int n)
  {
    final TreeMap<Long,List<K>> reverseMap =
         new TreeMap<>(new ReverseComparator<Long>());
    for (final Map.Entry<K,AtomicLong> e : m.entrySet())
    {
      final Long count = e.getValue().get();
      List<K> list = reverseMap.get(count);
      if (list == null)
      {
        list = new ArrayList<>(n);
        reverseMap.put(count, list);
      }
      list.add(e.getKey());
    }

    final ArrayList<ObjectPair<K,Long>> returnList = new ArrayList<>(n);
    for (final Map.Entry<Long,List<K>> e : reverseMap.entrySet())
    {
      final Long l = e.getKey();
      for (final K k : e.getValue())
      {
        returnList.add(new ObjectPair<>(k, l));
      }

      if (returnList.size() >= n)
      {
        break;
      }
    }

    return returnList;
  }



  /**
   * Writes a breakdown of the processing times for a specified type of
   * operation.
   *
   * @param  t  The name of the operation type.
   * @param  n  The total number of operations of the specified type that were
   *            processed by the server.
   * @param  m  The map of operation counts by processing time bucket.
   */
  private void printProcessingTimeHistogram(final String t, final long n,
                    final LinkedHashMap<Long,AtomicLong> m)
  {
    if (n <= 0)
    {
      return;
    }

    out();
    out("Count of ", t, " operations by processing time:");

    long lowerBound = 0;
    long accumulatedCount = 0;
    final Iterator<Map.Entry<Long,AtomicLong>> i = m.entrySet().iterator();
    while (i.hasNext())
    {
      final Map.Entry<Long,AtomicLong> e = i.next();
      final long upperBound = e.getKey();
      final long count = e.getValue().get();
      final double categoryPercent = 100.0 * count / n;

      accumulatedCount += count;
      final double accumulatedPercent = 100.0 * accumulatedCount / n;

      if (i.hasNext())
      {
        out("Between ", lowerBound, "ms and ", upperBound, "ms:  ",
            count, " (", decimalFormat.format(categoryPercent), "%, ",
            decimalFormat.format(accumulatedPercent), "% accumulated)");
        lowerBound = upperBound;
      }
      else
      {
        out("Greater than ", lowerBound, "ms:  ", count, " (",
            decimalFormat.format(categoryPercent), "%, ",
            decimalFormat.format(accumulatedPercent), "% accumulated)");
      }
    }
  }



  /**
   * Optionally prints information about the number and percent of operations of
   * the specified type that involved access to uncached data.
   *
   * @param  operationType  The type of operation.
   * @param  numUncached    The number of operations of the specified type that
   *                        involved access to uncached data.
   * @param  numTotal       The total number of operations of the specified
   *                        type.
   */
  private void printUncached(final String operationType, final long numUncached,
                             final long numTotal)
  {
    if (numUncached == 0)
    {
      return;
    }

    out(operationType, ":  ", numUncached, " (",
         decimalFormat.format(100.0 * numUncached / numTotal), "%)");
  }
}
