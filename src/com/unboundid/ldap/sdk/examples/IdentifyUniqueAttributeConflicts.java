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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DereferencePolicy;
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
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
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
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides a tool that may be used to identify unique attribute
 * conflicts (i.e., attributes which are supposed to be unique but for which
 * some values exist in multiple entries).
 * <BR><BR>
 * All of the necessary information is provided using command line arguments.
 * Supported arguments include those allowed by the {@link LDAPCommandLineTool}
 * class, as well as the following additional arguments:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies the base DN to use
 *       for the searches.  At least one base DN must be provided.</LI>
 *   <LI>"-f" {filter}" or "--filter "{filter}" -- specifies an optional
 *       filter to use for identifying entries across which uniqueness should be
 *       enforced.  If this is not provided, then all entries containing the
 *       target attribute(s) will be examined.</LI>
 *   <LI>"-A {attribute}" or "--attribute {attribute}" -- specifies an attribute
 *       for which to enforce uniqueness.  At least one unique attribute must be
 *       provided.</LI>
 *   <LI>"-m {behavior}" or "--multipleAttributeBehavior {behavior}" --
 *       specifies the behavior that the tool should exhibit if multiple
 *       unique attributes are provided.  Allowed values include
 *       unique-within-each-attribute,
 *       unique-across-all-attributes-including-in-same-entry,
 *       unique-across-all-attributes-except-in-same-entry, and
 *       unique-in-combination.</LI>
 *   <LI>"-z {size}" or "--simplePageSize {size}" -- indicates that the search
 *       to find entries with unique attributes should use the simple paged
 *       results control to iterate across entries in fixed-size pages rather
 *       than trying to use a single search to identify all entries containing
 *       unique attributes.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class IdentifyUniqueAttributeConflicts
       extends LDAPCommandLineTool
       implements SearchResultListener
{
  /**
   * The unique attribute behavior value that indicates uniqueness should only
   * be ensured within each attribute.
   */
  @NotNull private static final String BEHAVIOR_UNIQUE_WITHIN_ATTR =
       "unique-within-each-attribute";



  /**
   * The unique attribute behavior value that indicates uniqueness should be
   * ensured across all attributes, and conflicts will not be allowed across
   * attributes in the same entry.
   */
  @NotNull private static final String
       BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME =
            "unique-across-all-attributes-including-in-same-entry";



  /**
   * The unique attribute behavior value that indicates uniqueness should be
   * ensured across all attributes, except that conflicts will not be allowed
   * across attributes in the same entry.
   */
  @NotNull private static final String
       BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME =
            "unique-across-all-attributes-except-in-same-entry";



  /**
   * The unique attribute behavior value that indicates uniqueness should be
   * ensured for the combination of attribute values.
   */
  @NotNull private static final String BEHAVIOR_UNIQUE_IN_COMBINATION =
       "unique-in-combination";



  /**
   * The default value for the timeLimit argument.
   */
  private static final int DEFAULT_TIME_LIMIT_SECONDS = 10;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4216291898088659008L;



  // Indicates whether a TIME_LIMIT_EXCEEDED result has been encountered during
  // processing.
  @NotNull private final AtomicBoolean timeLimitExceeded;

  // The number of entries examined so far.
  @NotNull private final AtomicLong entriesExamined;

  // The number of conflicts found from a combination of attributes.
  @NotNull private final AtomicLong combinationConflictCounts;

  // Indicates whether cross-attribute uniqueness conflicts should be allowed
  // in the same entry.
  private boolean allowConflictsInSameEntry;

  // Indicates whether uniqueness should be enforced across all attributes
  // rather than within each attribute.
  private boolean uniqueAcrossAttributes;

  // Indicates whether uniqueness should be enforced for the combination
  // of attribute values.
  private boolean uniqueInCombination;

  // The argument used to specify the base DNs to use for searches.
  @Nullable private DNArgument baseDNArgument;

  // The argument used to specify a filter indicating which entries to examine.
  @Nullable private FilterArgument filterArgument;

  // The argument used to specify the search page size.
  @Nullable private IntegerArgument pageSizeArgument;

  // The argument used to specify the time limit for the searches used to find
  // conflicting entries.
  @Nullable private IntegerArgument timeLimitArgument;

  // The connection to use for finding unique attribute conflicts.
  @Nullable private LDAPConnectionPool findConflictsPool;

  // A map with counts of unique attribute conflicts by attribute type.
  @NotNull private final Map<String, AtomicLong> conflictCounts;

  // The names of the attributes for which to find uniqueness conflicts.
  @Nullable private String[] attributes;

  // The set of base DNs to use for the searches.
  @Nullable private String[] baseDNs;

  // The argument used to specify the attributes for which to find uniqueness
  // conflicts.
  @Nullable private StringArgument attributeArgument;

  // The argument used to specify the behavior that should be exhibited if
  // multiple attributes are specified.
  @Nullable private StringArgument multipleAttributeBehaviorArgument;


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
    final IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(outStream, errStream);
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
  public IdentifyUniqueAttributeConflicts(
              @Nullable final OutputStream outStream,
              @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    baseDNArgument = null;
    filterArgument = null;
    pageSizeArgument = null;
    attributeArgument = null;
    multipleAttributeBehaviorArgument = null;
    findConflictsPool = null;
    allowConflictsInSameEntry = false;
    uniqueAcrossAttributes = false;
    uniqueInCombination = false;
    attributes = null;
    baseDNs = null;
    timeLimitArgument = null;

    timeLimitExceeded = new AtomicBoolean(false);
    entriesExamined = new AtomicLong(0L);
    combinationConflictCounts = new AtomicLong(0L);
    conflictCounts = new TreeMap<>();
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "identify-unique-attribute-conflicts";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "This tool may be used to identify unique attribute conflicts.  " +
         "That is, it may identify values of one or more attributes which " +
         "are supposed to exist only in a single entry but are found in " +
         "multiple entries.";
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return A version string for this tool, or {@code null} if none is
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
   * @throws ArgumentException  If a problem occurs while adding the arguments.
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
       throws ArgumentException
  {
    String description = "The search base DN(s) to use to find entries with " +
         "attributes for which to find uniqueness conflicts.  At least one " +
         "base DN must be specified.";
    baseDNArgument = new DNArgument('b', "baseDN", true, 0, "{dn}",
         description);
    baseDNArgument.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDNArgument);

    description = "A filter that will be used to identify the set of " +
         "entries in which to identify uniqueness conflicts.  If this is not " +
         "specified, then all entries containing the target attribute(s) " +
         "will be examined.";
    filterArgument = new FilterArgument('f', "filter", false, 1, "{filter}",
         description);
    parser.addArgument(filterArgument);

    description = "The attributes for which to find uniqueness conflicts.  " +
         "At least one attribute must be specified, and each attribute " +
         "must be indexed for equality searches.";
    attributeArgument = new StringArgument('A', "attribute", true, 0, "{attr}",
         description);
    parser.addArgument(attributeArgument);

    description = "Indicates the behavior to exhibit if multiple unique " +
         "attributes are provided.  Allowed values are '" +
         BEHAVIOR_UNIQUE_WITHIN_ATTR + "' (indicates that each value only " +
         "needs to be unique within its own attribute type), '" +
         BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME + "' (indicates that " +
         "each value needs to be unique across all of the specified " +
         "attributes), '" + BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME +
         "' (indicates each value needs to be unique across all of the " +
         "specified attributes, except that multiple attributes in the same " +
         "entry are allowed to share the same value), and '" +
         BEHAVIOR_UNIQUE_IN_COMBINATION + "' (indicates that every " +
         "combination of the values of the specified attributes must be " +
         "unique across each entry).";
    final Set<String> allowedValues = StaticUtils.setOf(
         BEHAVIOR_UNIQUE_WITHIN_ATTR,
         BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME,
         BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME,
         BEHAVIOR_UNIQUE_IN_COMBINATION);
    multipleAttributeBehaviorArgument = new StringArgument('m',
         "multipleAttributeBehavior", false, 1, "{behavior}", description,
         allowedValues, BEHAVIOR_UNIQUE_WITHIN_ATTR);
    multipleAttributeBehaviorArgument.addLongIdentifier(
         "multiple-attribute-behavior", true);
    parser.addArgument(multipleAttributeBehaviorArgument);

    description = "The maximum number of entries to retrieve at a time when " +
         "attempting to find uniqueness conflicts.  This requires that the " +
         "authenticated user have permission to use the simple paged results " +
         "control, but it can avoid problems with the server sending entries " +
         "too quickly for the client to handle.  By default, the simple " +
         "paged results control will not be used.";
    pageSizeArgument =
         new IntegerArgument('z', "simplePageSize", false, 1, "{num}",
              description, 1, Integer.MAX_VALUE);
    pageSizeArgument.addLongIdentifier("simple-page-size", true);
    parser.addArgument(pageSizeArgument);

    description = "The time limit in seconds that will be used for search " +
         "requests attempting to identify conflicts for each value of any of " +
         "the unique attributes.  This time limit is used to avoid sending " +
         "expensive unindexed search requests that can consume significant " +
         "server resources.  If any of these search operations fails in a " +
         "way that indicates the requested time limit was exceeded, the " +
         "tool will abort its processing.  A value of zero indicates that no " +
         "time limit will be enforced.  If this argument is not provided, a " +
         "default time limit of " + DEFAULT_TIME_LIMIT_SECONDS +
         " will be used.";
    timeLimitArgument = new IntegerArgument('l', "timeLimitSeconds", false, 1,
         "{num}", description, 0, Integer.MAX_VALUE,
         DEFAULT_TIME_LIMIT_SECONDS);
    timeLimitArgument.addLongIdentifier("timeLimit", true);
    timeLimitArgument.addLongIdentifier("time-limit-seconds", true);
    timeLimitArgument.addLongIdentifier("time-limit", true);

    parser.addArgument(timeLimitArgument);
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
    // Determine the multi-attribute behavior that we should exhibit.
    final List<String> attrList = attributeArgument.getValues();
    final String multiAttrBehavior =
         multipleAttributeBehaviorArgument.getValue();
    if (attrList.size() > 1)
    {
      if (multiAttrBehavior.equalsIgnoreCase(
           BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME))
      {
        uniqueAcrossAttributes = true;
        uniqueInCombination = false;
        allowConflictsInSameEntry = false;
      }
      else if (multiAttrBehavior.equalsIgnoreCase(
           BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME))
      {
        uniqueAcrossAttributes = true;
        uniqueInCombination = false;
        allowConflictsInSameEntry = true;
      }
      else if (multiAttrBehavior.equalsIgnoreCase(
           BEHAVIOR_UNIQUE_IN_COMBINATION))
      {
        uniqueAcrossAttributes = false;
        uniqueInCombination = true;
        allowConflictsInSameEntry = true;
      }
      else
      {
        uniqueAcrossAttributes = false;
        uniqueInCombination = false;
        allowConflictsInSameEntry = true;
      }
    }
    else
    {
      uniqueAcrossAttributes = false;
      uniqueInCombination = false;
      allowConflictsInSameEntry = true;
    }


    // Get the string representations of the base DNs.
    final List<DN> dnList = baseDNArgument.getValues();
    baseDNs = new String[dnList.size()];
    for (int i=0; i < baseDNs.length; i++)
    {
      baseDNs[i] = dnList.get(i).toString();
    }

    // Establish a connection to the target directory server to use for finding
    // entries with unique attributes.
    final LDAPConnectionPool findUniqueAttributesPool;
    try
    {
      findUniqueAttributesPool = getConnectionPool(1, 1);
      findUniqueAttributesPool.
           setRetryFailedOperationsDueToInvalidConnections(true);
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
      // Establish a connection to use for finding unique attribute conflicts.
      try
      {
        findConflictsPool= getConnectionPool(1, 1);
        findConflictsPool.setRetryFailedOperationsDueToInvalidConnections(true);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err("Unable to establish a connection to the directory server:  ",
             StaticUtils.getExceptionMessage(le));
        return le.getResultCode();
      }

      // Get the set of attributes for which to ensure uniqueness.
      attributes = new String[attrList.size()];
      attrList.toArray(attributes);


      // Construct a search filter that will be used to find all entries with
      // unique attributes.
      Filter filter;
      if (attributes.length == 1)
      {
        filter = Filter.createPresenceFilter(attributes[0]);
        conflictCounts.put(attributes[0], new AtomicLong(0L));
      }
      else if (uniqueInCombination)
      {
        final Filter[] andComps = new Filter[attributes.length];
        for (int i=0; i < attributes.length; i++)
        {
          andComps[i] = Filter.createPresenceFilter(attributes[i]);
          conflictCounts.put(attributes[i], new AtomicLong(0L));
        }
        filter = Filter.createANDFilter(andComps);
      }
      else
      {
        final Filter[] orComps = new Filter[attributes.length];
        for (int i=0; i < attributes.length; i++)
        {
          orComps[i] = Filter.createPresenceFilter(attributes[i]);
          conflictCounts.put(attributes[i], new AtomicLong(0L));
        }
        filter = Filter.createORFilter(orComps);
      }

      if (filterArgument.isPresent())
      {
        filter = Filter.createANDFilter(filterArgument.getValue(), filter);
      }

      // Iterate across all of the search base DNs and perform searches to find
      // unique attributes.
      for (final String baseDN : baseDNs)
      {
        ASN1OctetString cookie = null;
        do
        {
          if (timeLimitExceeded.get())
          {
            break;
          }

          final SearchRequest searchRequest = new SearchRequest(this, baseDN,
               SearchScope.SUB, filter, attributes);
          if (pageSizeArgument.isPresent())
          {
            searchRequest.addControl(new SimplePagedResultsControl(
                 pageSizeArgument.getValue(), cookie, false));
          }

          SearchResult searchResult;
          try
          {
            searchResult = findUniqueAttributesPool.search(searchRequest);
          }
          catch (final LDAPSearchException lse)
          {
            Debug.debugException(lse);
            try
            {
              searchResult = findConflictsPool.search(searchRequest);
            }
            catch (final LDAPSearchException lse2)
            {
              Debug.debugException(lse2);
              searchResult = lse2.getSearchResult();
            }
          }

          if (searchResult.getResultCode() != ResultCode.SUCCESS)
          {
            err("An error occurred while attempting to search for unique " +
                 "attributes in entries below " + baseDN + ":  " +
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


      // See if there were any uniqueness conflicts found.
      boolean conflictFound = false;
      if (uniqueInCombination)
      {
        final long count = combinationConflictCounts.get();
        if (count > 0L)
        {
          conflictFound = true;
          err("Found " + count + " total conflicts.");
        }
      }
      else
      {
        for (final Map.Entry<String,AtomicLong> e : conflictCounts.entrySet())
        {
          final long numConflicts = e.getValue().get();
          if (numConflicts > 0L)
          {
            if (! conflictFound)
            {
              err();
              conflictFound = true;
            }

            err("Found " + numConflicts +
                 " unique value conflicts in attribute " + e.getKey());
          }
        }
      }

      if (conflictFound)
      {
        return ResultCode.CONSTRAINT_VIOLATION;
      }
      else if (timeLimitExceeded.get())
      {
        return ResultCode.TIME_LIMIT_EXCEEDED;
      }
      else
      {
        out("No unique attribute conflicts were found.");
        return ResultCode.SUCCESS;
      }
    }
    finally
    {
      findUniqueAttributesPool.close();

      if (findConflictsPool != null)
      {
        findConflictsPool.close();
      }
    }
  }



  /**
   * Retrieves the number of conflicts identified across multiple attributes in
   * combination.
   *
   * @return  The number of conflicts identified across multiple attributes in
   *          combination.
   */
  public long getCombinationConflictCounts()
  {
    return combinationConflictCounts.get();
  }



  /**
   * Retrieves a map that correlates the number of uniqueness conflicts found by
   * attribute type.
   *
   * @return  A map that correlates the number of uniqueness conflicts found by
   *          attribute type.
   */
  @NotNull()
  public Map<String,AtomicLong> getConflictCounts()
  {
    return Collections.unmodifiableMap(conflictCounts);
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
      "--attribute", "uid",
      "--simplePageSize", "100"
    };
    exampleMap.put(args,
         "Identify any values of the uid attribute that are not unique " +
              "across all entries below dc=example,dc=com.");

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
  public void searchEntryReturned(
                   @NotNull final SearchResultEntry searchEntry)
  {
    // If we have encountered a "time limit exceeded" error, then don't even
    // bother processing any more entries.
    if (timeLimitExceeded.get())
    {
      return;
    }

    if (uniqueInCombination)
    {
      checkForConflictsInCombination(searchEntry);
      return;
    }

    try
    {
      // If we need to check for conflicts in the same entry, then do that
      // first.
      if (! allowConflictsInSameEntry)
      {
        boolean conflictFound = false;
        for (int i=0; i < attributes.length; i++)
        {
          final List<Attribute> l1 =
               searchEntry.getAttributesWithOptions(attributes[i], null);
          if (l1 != null)
          {
            for (int j=i+1; j < attributes.length; j++)
            {
              final List<Attribute> l2 =
                   searchEntry.getAttributesWithOptions(attributes[j], null);
              if (l2 != null)
              {
                for (final Attribute a1 : l1)
                {
                  for (final String value : a1.getValues())
                  {
                    for (final Attribute a2 : l2)
                    {
                      if (a2.hasValue(value))
                      {
                        err("Value '", value, "' in attribute ", a1.getName(),
                             " of entry '", searchEntry.getDN(),
                             " is also present in attribute ", a2.getName(),
                             " of the same entry.");
                        conflictFound = true;
                        conflictCounts.get(attributes[i]).incrementAndGet();
                      }
                    }
                  }
                }
              }
            }
          }
        }

        if (conflictFound)
        {
          return;
        }
      }


      // Get the unique attributes from the entry and search for conflicts with
      // each value in other entries.  Although we could theoretically do this
      // with fewer searches, most uses of unique attributes don't have multiple
      // values, so the following code (which is much simpler) is just as
      // efficient in the common case.
      for (final String attrName : attributes)
      {
        final List<Attribute> attrList =
             searchEntry.getAttributesWithOptions(attrName, null);
        for (final Attribute a : attrList)
        {
          for (final String value : a.getValues())
          {
            Filter filter;
            if (uniqueAcrossAttributes)
            {
              final Filter[] orComps = new Filter[attributes.length];
              for (int i=0; i < attributes.length; i++)
              {
                orComps[i] = Filter.createEqualityFilter(attributes[i], value);
              }
              filter = Filter.createORFilter(orComps);
            }
            else
            {
              filter = Filter.createEqualityFilter(attrName, value);
            }

            if (filterArgument.isPresent())
            {
              filter = Filter.createANDFilter(filterArgument.getValue(),
                   filter);
            }

baseDNLoop:
            for (final String baseDN : baseDNs)
            {
              SearchResult searchResult;
              final SearchRequest searchRequest = new SearchRequest(baseDN,
                   SearchScope.SUB, DereferencePolicy.NEVER, 2,
                   timeLimitArgument.getValue(), false, filter, "1.1");
              try
              {
                searchResult = findConflictsPool.search(searchRequest);
              }
              catch (final LDAPSearchException lse)
              {
                Debug.debugException(lse);
                if (lse.getResultCode() == ResultCode.TIME_LIMIT_EXCEEDED)
                {
                  // The server spent more time than the configured time limit
                  // to process the search.  This almost certainly means that
                  // the search is unindexed, and we don't want to continue.
                  // Indicate that the time limit has been exceeded, cancel the
                  // outer search, and display an error message to the user.
                  timeLimitExceeded.set(true);
                  try
                  {
                    findConflictsPool.processExtendedOperation(
                         new CancelExtendedRequest(searchEntry.getMessageID()));
                  }
                  catch (final Exception e)
                  {
                    Debug.debugException(e);
                  }

                  err("A server-side time limit was exceeded when searching " +
                       "below base DN '" + baseDN + "' with filter '" +
                       filter + "', which likely means that the search " +
                       "request is not indexed in the server.  Check the " +
                       "server configuration to ensure that any appropriate " +
                       "indexes are in place.  To indicate that searches " +
                       "should not request any time limit, use the " +
                       timeLimitArgument.getIdentifierString() +
                       " to indicate a time limit of zero seconds.");
                  return;
                }
                else if (lse.getResultCode().isConnectionUsable())
                {
                  searchResult = lse.getSearchResult();
                }
                else
                {
                  try
                  {
                    searchResult = findConflictsPool.search(searchRequest);
                  }
                  catch (final LDAPSearchException lse2)
                  {
                    Debug.debugException(lse2);
                    searchResult = lse2.getSearchResult();
                  }
                }
              }

              for (final SearchResultEntry e : searchResult.getSearchEntries())
              {
                try
                {
                  if (DN.equals(searchEntry.getDN(), e.getDN()))
                  {
                    continue;
                  }
                }
                catch (final Exception ex)
                {
                  Debug.debugException(ex);
                }

                err("Value '", value, "' in attribute ", a.getName(),
                     " of entry '" + searchEntry.getDN(),
                     "' is also present in entry '", e.getDN(), "'.");
                conflictCounts.get(attrName).incrementAndGet();
                break baseDNLoop;
              }

              if (searchResult.getResultCode() != ResultCode.SUCCESS)
              {
                err("An error occurred while attempting to search for " +
                     "conflicts with " + a.getName() + " value '" + value +
                     "' (as found in entry '" + searchEntry.getDN() +
                     "') below '" + baseDN + "':  " +
                     searchResult.getDiagnosticMessage());
                conflictCounts.get(attrName).incrementAndGet();
                break baseDNLoop;
              }
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
   * Performs the processing necessary to check for conflicts between a
   * combination of attribute values obtained from the provided entry.
   *
   * @param  entry  The entry to examine.
   */
  private void checkForConflictsInCombination(
                    @NotNull final SearchResultEntry entry)
  {
    // Construct a filter used to identify conflicting entries as an AND for
    // each attribute.  Handle the possibility of multivalued attributes by
    // creating an OR of all values for each attribute.  And if an additional
    // filter was also specified, include it in the AND as well.
    final ArrayList<Filter> andComponents =
         new ArrayList<>(attributes.length + 1);
    for (final String attrName : attributes)
    {
      final LinkedHashSet<Filter> values =
           new LinkedHashSet<>(StaticUtils.computeMapCapacity(5));
      for (final Attribute a : entry.getAttributesWithOptions(attrName, null))
      {
        for (final byte[] value : a.getValueByteArrays())
        {
          final Filter equalityFilter =
               Filter.createEqualityFilter(attrName, value);
          values.add(Filter.createEqualityFilter(attrName, value));
        }
      }

      switch (values.size())
      {
        case 0:
          // This means that the returned entry didn't include any values for
          // the target attribute.  This should only happen if the user doesn't
          // have permission to see those values.  At any rate, we can't check
          // this entry for conflicts, so just assume there aren't any.
          return;

        case 1:
          andComponents.add(values.iterator().next());
          break;

        default:
          andComponents.add(Filter.createORFilter(values));
          break;
      }
    }

    if (filterArgument.isPresent())
    {
      andComponents.add(filterArgument.getValue());
    }

    final Filter filter = Filter.createANDFilter(andComponents);


    // Search below each of the configured base DNs.
baseDNLoop:
    for (final DN baseDN : baseDNArgument.getValues())
    {
      SearchResult searchResult;
      final SearchRequest searchRequest = new SearchRequest(baseDN.toString(),
           SearchScope.SUB, DereferencePolicy.NEVER, 2,
           timeLimitArgument.getValue(), false, filter, "1.1");

      try
      {
        searchResult = findConflictsPool.search(searchRequest);
      }
      catch (final LDAPSearchException lse)
      {
        Debug.debugException(lse);
        if (lse.getResultCode() == ResultCode.TIME_LIMIT_EXCEEDED)
        {
          // The server spent more time than the configured time limit to
          // process the search.  This almost certainly means that the search is
          // unindexed, and we don't want to continue. Indicate that the time
          // limit has been exceeded, cancel the outer search, and display an
          // error message to the user.
          timeLimitExceeded.set(true);
          try
          {
            findConflictsPool.processExtendedOperation(
                 new CancelExtendedRequest(entry.getMessageID()));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }

          err("A server-side time limit was exceeded when searching below " +
               "base DN '" + baseDN + "' with filter '" + filter +
               "', which likely means that the search request is not indexed " +
               "in the server.  Check the server configuration to ensure " +
               "that any appropriate indexes are in place.  To indicate that " +
               "searches should not request any time limit, use the " +
               timeLimitArgument.getIdentifierString() +
               " to indicate a time limit of zero seconds.");
          return;
        }
        else if (lse.getResultCode().isConnectionUsable())
        {
          searchResult = lse.getSearchResult();
        }
        else
        {
          try
          {
            searchResult = findConflictsPool.search(searchRequest);
          }
          catch (final LDAPSearchException lse2)
          {
            Debug.debugException(lse2);
            searchResult = lse2.getSearchResult();
          }
        }
      }

      for (final SearchResultEntry e : searchResult.getSearchEntries())
      {
        try
        {
          if (DN.equals(entry.getDN(), e.getDN()))
          {
            continue;
          }
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
        }

        err("Entry '" + entry.getDN() + " has a combination of values that " +
             "are also present in entry '" + e.getDN() + "'.");
        combinationConflictCounts.incrementAndGet();
        break baseDNLoop;
      }

      if (searchResult.getResultCode() != ResultCode.SUCCESS)
      {
        err("An error occurred while attempting to search for conflicts " +
             " with entry '" + entry.getDN() + "' below '" + baseDN + "':  " +
             searchResult.getDiagnosticMessage());
        combinationConflictCounts.incrementAndGet();
        break baseDNLoop;
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
