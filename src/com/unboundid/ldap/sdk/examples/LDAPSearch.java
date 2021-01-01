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
package com.unboundid.ldap.sdk.examples;



import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.WakeableSleeper;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;



/**
 * This class provides a simple tool that can be used to search an LDAP
 * directory server.  Some of the APIs demonstrated by this example include:
 * <UL>
 *   <LI>Argument Parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 *   <LI>LDAP Command-Line Tool (from the {@code com.unboundid.util}
 *       package)</LI>
 *   <LI>LDAP Communication (from the {@code com.unboundid.ldap.sdk}
 *       package)</LI>
 * </UL>
 * <BR><BR>
 * All of the necessary information is provided using
 * command line arguments.  Supported arguments include those allowed by the
 * {@link LDAPCommandLineTool} class, as well as the following additional
 * arguments:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies the base DN to use
 *       for the search.  This must be provided.</LI>
 *   <LI>"-s {scope}" or "--scope {scope}" -- specifies the scope to use for the
 *       search.  The scope value should be one of "base", "one", "sub", or
 *       "subord".  If this isn't specified, then a scope of "sub" will be
 *       used.</LI>
 *   <LI>"-R" or "--followReferrals" -- indicates that the tool should follow
 *       any referrals encountered while searching.</LI>
 *   <LI>"-t" or "--terse" -- indicates that the tool should generate minimal
 *       output beyond the search results.</LI>
 *   <LI>"-i {millis}" or "--repeatIntervalMillis {millis}" -- indicates that
 *       the search should be periodically repeated with the specified delay
 *       (in milliseconds) between requests.</LI>
 *   <LI>"-n {count}" or "--numSearches {count}" -- specifies the total number
 *       of times that the search should be performed.  This may only be used in
 *       conjunction with the "--repeatIntervalMillis" argument.  If
 *       "--repeatIntervalMillis" is used without "--numSearches", then the
 *       searches will continue to be repeated until the tool is
 *       interrupted.</LI>
 *   <LI>"--bindControl {control}" -- specifies a control that should be
 *       included in the bind request sent by this tool before performing any
 *       search operations.</LI>
 *   <LI>"-J {control}" or "--control {control}" -- specifies a control that
 *       should be included in the search request(s) sent by this tool.</LI>
 * </UL>
 * In addition, after the above named arguments are provided, a set of one or
 * more unnamed trailing arguments must be given.  The first argument should be
 * the string representation of the filter to use for the search.  If there are
 * any additional trailing arguments, then they will be interpreted as the
 * attributes to return in matching entries.  If no attribute names are given,
 * then the server should return all user attributes in matching entries.
 * <BR><BR>
 * Note that this class implements the SearchResultListener interface, which
 * will be notified whenever a search result entry or reference is returned from
 * the server.  Whenever an entry is received, it will simply be printed
 * displayed in LDIF.
 *
 * @see  com.unboundid.ldap.sdk.unboundidds.tools.LDAPSearch
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPSearch
       extends LDAPCommandLineTool
       implements SearchResultListener
{
  /**
   * The date formatter that should be used when writing timestamps.
   */
  @NotNull private static final SimpleDateFormat DATE_FORMAT =
       new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss.SSS");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7465188734621412477L;



  // The argument parser used by this program.
  @Nullable private ArgumentParser parser;

  // Indicates whether the search should be repeated.
  private boolean repeat;

  // The argument used to indicate whether to follow referrals.
  @Nullable private BooleanArgument followReferrals;

  // The argument used to indicate whether to use terse mode.
  @Nullable private BooleanArgument terseMode;

  // The argument used to specify any bind controls that should be used.
  @Nullable private ControlArgument bindControls;

  // The argument used to specify any search controls that should be used.
  @Nullable private ControlArgument searchControls;

  // The number of times to perform the search.
  @Nullable private IntegerArgument numSearches;

  // The interval in milliseconds between repeated searches.
  @Nullable private IntegerArgument repeatIntervalMillis;

  // The argument used to specify the base DN for the search.
  @Nullable private DNArgument baseDN;

  // The argument used to specify the scope for the search.
  @Nullable private ScopeArgument scopeArg;



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
    final LDAPSearch ldapSearch = new LDAPSearch(outStream, errStream);
    return ldapSearch.runTool(args);
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
  public LDAPSearch(@Nullable final OutputStream outStream,
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
    return "ldapsearch";
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
    return "Search an LDAP directory server.";
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
   * Retrieves the minimum number of unnamed trailing arguments that are
   * required.
   *
   * @return  One, to indicate that at least one trailing argument (representing
   *          the search filter) must be provided.
   */
  @Override()
  public int getMinTrailingArguments()
  {
    return 1;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that are
   * allowed.
   *
   * @return  A negative value to indicate that any number of trailing arguments
   *          may be provided.
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return -1;
  }



  /**
   * Retrieves a placeholder string that may be used to indicate what kinds of
   * trailing arguments are allowed.
   *
   * @return  A placeholder string that may be used to indicate what kinds of
   *          trailing arguments are allowed.
   */
  @Override()
  @NotNull()
  public String getTrailingArgumentsPlaceholder()
  {
    return "{filter} [attr1 [attr2 [...]]]";
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

    String description = "The base DN to use for the search.  This must be " +
                         "provided.";
    baseDN = new DNArgument('b', "baseDN", true, 1, "{dn}", description);
    baseDN.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDN);


    description = "The scope to use for the search.  It should be 'base', " +
                  "'one', 'sub', or 'subord'.  If this is not provided, then " +
                  "a default scope of 'sub' will be used.";
    scopeArg = new ScopeArgument('s', "scope", false, "{scope}", description,
                                 SearchScope.SUB);
    parser.addArgument(scopeArg);


    description = "Follow any referrals encountered during processing.";
    followReferrals = new BooleanArgument('R', "followReferrals", description);
    followReferrals.addLongIdentifier("follow-referrals", true);
    parser.addArgument(followReferrals);


    description = "Information about a control to include in the bind request.";
    bindControls = new ControlArgument(null, "bindControl", false, 0, null,
         description);
    bindControls.addLongIdentifier("bind-control", true);
    parser.addArgument(bindControls);


    description = "Information about a control to include in search requests.";
    searchControls = new ControlArgument('J', "control", false, 0, null,
         description);
    parser.addArgument(searchControls);


    description = "Generate terse output with minimal additional information.";
    terseMode = new BooleanArgument('t', "terse", description);
    parser.addArgument(terseMode);


    description = "Specifies the length of time in milliseconds to sleep " +
                  "before repeating the same search.  If this is not " +
                  "provided, then the search will only be performed once.";
    repeatIntervalMillis = new IntegerArgument('i', "repeatIntervalMillis",
                                               false, 1, "{millis}",
                                               description, 0,
                                               Integer.MAX_VALUE);
    repeatIntervalMillis.addLongIdentifier("repeat-interval-millis", true);
    parser.addArgument(repeatIntervalMillis);


    description = "Specifies the number of times that the search should be " +
                  "performed.  If this argument is present, then the " +
                  "--repeatIntervalMillis argument must also be provided to " +
                  "specify the length of time between searches.  If " +
                  "--repeatIntervalMillis is used without --numSearches, " +
                  "then the search will be repeated until the tool is " +
                  "interrupted.";
    numSearches = new IntegerArgument('n', "numSearches", false, 1, "{count}",
                                      description, 1, Integer.MAX_VALUE);
    numSearches.addLongIdentifier("num-searches", true);
    parser.addArgument(numSearches);
    parser.addDependentArgumentSet(numSearches, repeatIntervalMillis);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // There must have been at least one trailing argument provided, and it must
    // be parsable as a valid search filter.
    if (parser.getTrailingArguments().isEmpty())
    {
      throw new ArgumentException("At least one trailing argument must be " +
           "provided to specify the search filter.  Additional trailing " +
           "arguments are allowed to specify the attributes to return in " +
           "search result entries.");
    }

    try
    {
      Filter.create(parser.getTrailingArguments().get(0));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           "The first trailing argument value could not be parsed as a valid " +
                "LDAP search filter.",
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Control> getBindControls()
  {
    return bindControls.getValues();
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
    // Make sure that at least one trailing argument was provided, which will be
    // the filter.  If there were any other arguments, then they will be the
    // attributes to return.
    final List<String> trailingArguments = parser.getTrailingArguments();
    if (trailingArguments.isEmpty())
    {
      err("No search filter was provided.");
      err();
      err(parser.getUsageString(StaticUtils.TERMINAL_WIDTH_COLUMNS - 1));
      return ResultCode.PARAM_ERROR;
    }

    final Filter filter;
    try
    {
      filter = Filter.create(trailingArguments.get(0));
    }
    catch (final LDAPException le)
    {
      err("Invalid search filter:  ", le.getMessage());
      return le.getResultCode();
    }

    final String[] attributesToReturn;
    if (trailingArguments.size() > 1)
    {
      attributesToReturn = new String[trailingArguments.size() - 1];
      for (int i=1; i < trailingArguments.size(); i++)
      {
        attributesToReturn[i-1] = trailingArguments.get(i);
      }
    }
    else
    {
      attributesToReturn = StaticUtils.NO_STRINGS;
    }


    // Get the connection to the directory server.
    final LDAPConnection connection;
    try
    {
      connection = getConnection();
      if (! terseMode.isPresent())
      {
        out("# Connected to ", connection.getConnectedAddress(), ':',
             connection.getConnectedPort());
      }
    }
    catch (final LDAPException le)
    {
      err("Error connecting to the directory server:  ", le.getMessage());
      return le.getResultCode();
    }


    // Create a search request with the appropriate information and process it
    // in the server.  Note that in this case, we're creating a search result
    // listener to handle the results since there could potentially be a lot of
    // them.
    final SearchRequest searchRequest =
         new SearchRequest(this, baseDN.getStringValue(), scopeArg.getValue(),
                           DereferencePolicy.NEVER, 0, 0, false, filter,
                           attributesToReturn);
    searchRequest.setFollowReferrals(followReferrals.isPresent());

    final List<Control> controlList = searchControls.getValues();
    if (controlList != null)
    {
      searchRequest.setControls(controlList);
    }


    final boolean infinite;
    final int numIterations;
    if (repeatIntervalMillis.isPresent())
    {
      repeat = true;

      if (numSearches.isPresent())
      {
        infinite      = false;
        numIterations = numSearches.getValue();
      }
      else
      {
        infinite      = true;
        numIterations = Integer.MAX_VALUE;
      }
    }
    else
    {
      infinite      = false;
      repeat        = false;
      numIterations = 1;
    }

    ResultCode resultCode = ResultCode.SUCCESS;
    long lastSearchTime = System.currentTimeMillis();
    final WakeableSleeper sleeper = new WakeableSleeper();
    for (int i=0; (infinite || (i < numIterations)); i++)
    {
      if (repeat && (i > 0))
      {
        final long sleepTime =
             (lastSearchTime + repeatIntervalMillis.getValue()) -
             System.currentTimeMillis();
        if (sleepTime > 0)
        {
          sleeper.sleep(sleepTime);
        }
        lastSearchTime = System.currentTimeMillis();
      }

      try
      {
        final SearchResult searchResult = connection.search(searchRequest);
        if ((! repeat) && (! terseMode.isPresent()))
        {
          out("# The search operation was processed successfully.");
          out("# Entries returned:  ", searchResult.getEntryCount());
          out("# References returned:  ", searchResult.getReferenceCount());
        }
      }
      catch (final LDAPException le)
      {
        err("An error occurred while processing the search:  ",
             le.getMessage());
        err("Result Code:  ", le.getResultCode().intValue(), " (",
             le.getResultCode().getName(), ')');
        if (le.getMatchedDN() != null)
        {
          err("Matched DN:  ", le.getMatchedDN());
        }

        if (le.getReferralURLs() != null)
        {
          for (final String url : le.getReferralURLs())
          {
            err("Referral URL:  ", url);
          }
        }

        if (resultCode == ResultCode.SUCCESS)
        {
          resultCode = le.getResultCode();
        }

        if (! le.getResultCode().isConnectionUsable())
        {
          break;
        }
      }
    }


    // Close the connection to the directory server and exit.
    connection.close();
    if (! terseMode.isPresent())
    {
      out();
      out("# Disconnected from the server");
    }
    return resultCode;
  }



  /**
   * Indicates that the provided search result entry was returned from the
   * associated search operation.
   *
   * @param  entry  The entry that was returned from the search.
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry entry)
  {
    if (repeat)
    {
      out("# ", DATE_FORMAT.format(new Date()));
    }

    out(entry.toLDIFString());
  }



  /**
   * Indicates that the provided search result reference was returned from the
   * associated search operation.
   *
   * @param  reference  The reference that was returned from the search.
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference reference)
  {
    if (repeat)
    {
      out("# ", DATE_FORMAT.format(new Date()));
    }

    out(reference.toString());
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
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "dc=example,dc=com",
      "--scope", "sub",
      "(uid=jdoe)",
      "givenName",
       "sn",
       "mail"
    };
    final String description =
         "Perform a search in the directory server to find all entries " +
         "matching the filter '(uid=jdoe)' anywhere below " +
         "'dc=example,dc=com'.  Include only the givenName, sn, and mail " +
         "attributes in the entries that are returned.";
    examples.put(args, description);

    return examples;
  }
}
