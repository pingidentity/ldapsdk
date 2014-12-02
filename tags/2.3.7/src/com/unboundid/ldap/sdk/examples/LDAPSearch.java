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
package com.unboundid.ldap.sdk.examples;



import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

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
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.WakeableSleeper;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
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
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPSearch
       extends LDAPCommandLineTool
       implements SearchResultListener
{
  /**
   * The date formatter that should be used when writing timestamps.
   */
  private static final SimpleDateFormat DATE_FORMAT =
       new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss.SSS");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7465188734621412477L;



  // The argument parser used by this program.
  private ArgumentParser parser;

  // Indicates whether the search should be repeated.
  private boolean repeat;

  // The argument used to indicate whether to follow referrals.
  private BooleanArgument followReferrals;

  // The argument used to indicate whether to use terse mode.
  private BooleanArgument terseMode;

  // The number of times to perform the search.
  private IntegerArgument numSearches;

  // The interval in milliseconds between repeated searches.
  private IntegerArgument repeatIntervalMillis;

  // The argument used to specify the base DN for the search.
  private DNArgument baseDN;

  // The argument used to specify the scope for the search.
  private ScopeArgument scopeArg;



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
  public LDAPSearch(final OutputStream outStream, final OutputStream errStream)
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
    return "ldapsearch";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
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
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
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
  public String getTrailingArgumentsPlaceholder()
  {
    return "{filter} [attr1 [attr2 [...]]]";
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
    this.parser = parser;

    String description = "The base DN to use for the search.  This must be " +
                         "provided.";
    baseDN = new DNArgument('b', "baseDN", true, 1, "{dn}", description);
    parser.addArgument(baseDN);


    description = "The scope to use for the search.  It should be 'base', " +
                  "'one', 'sub', or 'subord'.  If this is not provided, then " +
                  "a default scope of 'sub' will be used.";
    scopeArg = new ScopeArgument('s', "scope", false, "{scope}", description,
                                 SearchScope.SUB);
    parser.addArgument(scopeArg);


    description = "Follow any referrals encountered during processing.";
    followReferrals = new BooleanArgument('R', "followReferrals", description);
    parser.addArgument(followReferrals);


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
    parser.addArgument(numSearches);
    parser.addDependentArgumentSet(numSearches, repeatIntervalMillis);
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
    // Make sure that at least one trailing argument was provided, which will be
    // the filter.  If there were any other arguments, then they will be the
    // attributes to return.
    final List<String> trailingArguments = parser.getTrailingArguments();
    if (trailingArguments.isEmpty())
    {
      err("No search filter was provided.");
      err();
      err(parser.getUsageString(79));
      return ResultCode.PARAM_ERROR;
    }

    final Filter filter;
    try
    {
      filter = Filter.create(trailingArguments.get(0));
    }
    catch (LDAPException le)
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
    catch (LDAPException le)
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
      catch (LDAPException le)
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
  public void searchEntryReturned(final SearchResultEntry entry)
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
  public void searchReferenceReturned(final SearchResultReference reference)
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
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>();

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
