/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a tool that may be used to identify references to entries
 * that do not exist.  This tool can be useful for verifying existing data in
 * directory servers that provide support for referential integrity.
 * <BR><BR>
 * All of the necessary information is provided using command line arguments.
 * Supported arguments include those allowed by the {@link LDAPCommandLineTool}
 * class, as well as the following additional arguments:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies the base DN to use
 *       for the searches.  At least one base DN must be provided.</LI>
 *   <LI>"-A {attribute}" or "--attribute {attribute}" -- specifies an attribute
 *       that is expected to contain references to other entries.  This
 *       attribute should be indexed for equality searches, and its values
 *       should be DNs.  At least one attribute must be provided.</LI>
 *   <LI>"-z {size}" or "--simplePageSize {size}" -- indicates that the search
 *       to find entries with references to other entries should use the simple
 *       paged results control to iterate across entries in fixed-size pages
 *       rather than trying to use a single search to identify all entries that
 *       reference other entries.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class IdentifyReferencesToMissingEntries
       extends LDAPCommandLineTool
       implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1981894839719501258L;



  // The number of entries examined so far.
  @NotNull private final AtomicLong entriesExamined;

  // The argument used to specify the base DNs to use for searches.
  @Nullable private DNArgument baseDNArgument;

  // The argument used to specify the search page size.
  @Nullable private IntegerArgument pageSizeArgument;

  // The connection to use for retrieving referenced entries.
  @Nullable private LDAPConnectionPool getReferencedEntriesPool;

  // A map with counts of missing references by attribute type.
  @NotNull private final Map<String,AtomicLong> missingReferenceCounts;

  // The names of the attributes for which to find missing references.
  @Nullable private String[] attributes;

  // The argument used to specify the attributes for which to find missing
  // references.
  @Nullable private StringArgument attributeArgument;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
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
   * @return A result code indicating whether the processing was successful.
   */
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream)
  {
    final IdentifyReferencesToMissingEntries tool =
         new IdentifyReferencesToMissingEntries(outStream, errStream);
    return tool.runTool(args);
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
  public IdentifyReferencesToMissingEntries(
              @Nullable final OutputStream outStream,
              @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    baseDNArgument = null;
    pageSizeArgument = null;
    attributeArgument = null;
    getReferencedEntriesPool = null;

    entriesExamined = new AtomicLong(0L);
    missingReferenceCounts = new TreeMap<>();
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
    return "identify-references-to-missing-entries";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "This tool may be used to identify entries containing one or more " +
         "attributes which reference entries that do not exist.  This may " +
         "require the ability to perform unindexed searches and/or the " +
         "ability to use the simple paged results control.";
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
   * Adds the arguments needed by this command-line tool to the provided
   * argument parser which are not related to connecting or authenticating to
   * the directory server.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    String description = "The search base DN(s) to use to find entries with " +
         "references to other entries.  At least one base DN must be " +
         "specified.";
    baseDNArgument = new DNArgument('b', "baseDN", true, 0, "{dn}",
         description);
    baseDNArgument.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDNArgument);

    description = "The attribute(s) for which to find missing references.  " +
         "At least one attribute must be specified, and each attribute " +
         "must be indexed for equality searches and have values which are DNs.";
    attributeArgument = new StringArgument('A', "attribute", true, 0, "{attr}",
         description);
    parser.addArgument(attributeArgument);

    description = "The maximum number of entries to retrieve at a time when " +
         "attempting to find entries with references to other entries.  This " +
         "requires that the authenticated user have permission to use the " +
         "simple paged results control, but it can avoid problems with the " +
         "server sending entries too quickly for the client to handle.  By " +
         "default, the simple paged results control will not be used.";
    pageSizeArgument =
         new IntegerArgument('z', "simplePageSize", false, 1, "{num}",
              description, 1, Integer.MAX_VALUE);
    pageSizeArgument.addLongIdentifier("simple-page-size", true);
    parser.addArgument(pageSizeArgument);
  }



  /**
   * Retrieves the connection options that should be used for connections that
   * are created with this command line tool.  Subclasses may override this
   * method to use a custom set of connection options.
   *
   * @return  The connection options that should be used for connections that
   *          are created with this command line tool.
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();

    options.setUseSynchronousMode(true);
    options.setResponseTimeoutMillis(0L);

    return options;
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
    // Establish a connection to the target directory server to use for
    // finding references to entries.
    final LDAPConnectionPool findReferencesPool;
    try
    {
      findReferencesPool = getConnectionPool(1, 1);
      findReferencesPool.setRetryFailedOperationsDueToInvalidConnections(true);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err("Unable to establish a connection to the directory server:  ",
           StaticUtils.getExceptionMessage(le));
      return le.getResultCode();
    }

    try
    {
      // Establish a second connection to use for retrieving referenced entries.
      try
      {
        getReferencedEntriesPool = getConnectionPool(1,1);
        getReferencedEntriesPool.
             setRetryFailedOperationsDueToInvalidConnections(true);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err("Unable to establish a connection to the directory server:  ",
             StaticUtils.getExceptionMessage(le));
        return le.getResultCode();
      }


      // Get the set of attributes for which to find missing references.
      final List<String> attrList = attributeArgument.getValues();
      attributes = new String[attrList.size()];
      attrList.toArray(attributes);


      // Construct a search filter that will be used to find all entries with
      // references to other entries.
      final Filter filter;
      if (attributes.length == 1)
      {
        filter = Filter.createPresenceFilter(attributes[0]);
        missingReferenceCounts.put(attributes[0], new AtomicLong(0L));
      }
      else
      {
        final Filter[] orComps = new Filter[attributes.length];
        for (int i=0; i < attributes.length; i++)
        {
          orComps[i] = Filter.createPresenceFilter(attributes[i]);
          missingReferenceCounts.put(attributes[i], new AtomicLong(0L));
        }
        filter = Filter.createORFilter(orComps);
      }


      // Iterate across all of the search base DNs and perform searches to find
      // missing references.
      for (final DN baseDN : baseDNArgument.getValues())
      {
        ASN1OctetString cookie = null;
        do
        {
          final SearchRequest searchRequest = new SearchRequest(this,
               baseDN.toString(), SearchScope.SUB, filter, attributes);
          if (pageSizeArgument.isPresent())
          {
            searchRequest.addControl(new SimplePagedResultsControl(
                 pageSizeArgument.getValue(), cookie, false));
          }

          SearchResult searchResult;
          try
          {
            searchResult = findReferencesPool.search(searchRequest);
          }
          catch (final LDAPSearchException lse)
          {
            Debug.debugException(lse);
            try
            {
              searchResult = findReferencesPool.search(searchRequest);
            }
            catch (final LDAPSearchException lse2)
            {
              Debug.debugException(lse2);
              searchResult = lse2.getSearchResult();
            }
          }

          if (searchResult.getResultCode() != ResultCode.SUCCESS)
          {
            err("An error occurred while attempting to search for missing " +
                 "references to entries below " + baseDN + ":  " +
                 searchResult.getDiagnosticMessage());
            return searchResult.getResultCode();
          }

          final SimplePagedResultsControl pagedResultsResponse;
          try
          {
            pagedResultsResponse = SimplePagedResultsControl.get(searchResult);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            err("An error occurred while attempting to decode a simple " +
                 "paged results response control in the response to a " +
                 "search for entries below " + baseDN + ":  " +
                 StaticUtils.getExceptionMessage(le));
            return le.getResultCode();
          }

          if (pagedResultsResponse != null)
          {
            if (pagedResultsResponse.moreResultsToReturn())
            {
              cookie = pagedResultsResponse.getCookie();
            }
            else
            {
              cookie = null;
            }
          }
        }
        while (cookie != null);
      }


      // See if there were any missing references found.
      boolean missingReferenceFound = false;
      for (final Map.Entry<String,AtomicLong> e :
           missingReferenceCounts.entrySet())
      {
        final long numMissing = e.getValue().get();
        if (numMissing > 0L)
        {
          if (! missingReferenceFound)
          {
            err();
            missingReferenceFound = true;
          }

          err("Found " + numMissing + ' ' + e.getKey() +
               " references to entries that do not exist.");
        }
      }

      if (missingReferenceFound)
      {
        return ResultCode.CONSTRAINT_VIOLATION;
      }
      else
      {
        out("No references were found to entries that do not exist.");
        return ResultCode.SUCCESS;
      }
    }
    finally
    {
      findReferencesPool.close();

      if (getReferencedEntriesPool != null)
      {
        getReferencedEntriesPool.close();
      }
    }
  }



  /**
   * Retrieves a map that correlates the number of missing references found by
   * attribute type.
   *
   * @return  A map that correlates the number of missing references found by
   *          attribute type.
   */
  @NotNull()
  public Map<String,AtomicLong> getMissingReferenceCounts()
  {
    return Collections.unmodifiableMap(missingReferenceCounts);
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
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=john.doe,ou=People,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "dc=example,dc=com",
      "--attribute", "member",
      "--attribute", "uniqueMember",
      "--simplePageSize", "100"
    };
    exampleMap.put(args,
         "Identify all entries below dc=example,dc=com in which either the " +
              "member or uniqueMember attribute references an entry that " +
              "does not exist.");

    return exampleMap;
  }



  /**
   * Indicates that the provided search result entry has been returned by the
   * server and may be processed by this search result listener.
   *
   * @param  searchEntry  The search result entry that has been returned by the
   *                      server.
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    try
    {
      // Find attributes which references to entries that do not exist.
      for (final String attr : attributes)
      {
        final List<Attribute> attrList =
             searchEntry.getAttributesWithOptions(attr, null);
        for (final Attribute a : attrList)
        {
          for (final String value : a.getValues())
          {
            try
            {
              final SearchResultEntry e =
                   getReferencedEntriesPool.getEntry(value, "1.1");
              if (e == null)
              {
                err("Entry '", searchEntry.getDN(), "' includes attribute ",
                     a.getName(), " that references entry '", value,
                     "' which does not exist.");
                missingReferenceCounts.get(attr).incrementAndGet();
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
              err("An error occurred while attempting to determine whether " +
                   "entry '" + value + "' referenced in attribute " +
                   a.getName() + " of entry '" + searchEntry.getDN() +
                   "' exists:  " + StaticUtils.getExceptionMessage(le));
              missingReferenceCounts.get(attr).incrementAndGet();
            }
          }
        }
      }
    }
    finally
    {
      final long count = entriesExamined.incrementAndGet();
      if ((count % 1000L) == 0L)
      {
        out(count, " entries examined");
      }
    }
  }



  /**
   * Indicates that the provided search result reference has been returned by
   * the server and may be processed by this search result listener.
   *
   * @param  searchReference  The search result reference that has been returned
   *                          by the server.
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    // No implementation is required.  This tool will not follow referrals.
  }
}
