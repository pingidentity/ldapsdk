/*
 * Copyright 2013-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2014 UnboundID Corp.
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
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
 *   <LI>"-A {attribute}" or "--attribute {attribute}" -- specifies an attribute
 *       for which to enforce uniqueness.  At least one unique attribute must be
 *       provided.</LI>
 *   <LI>"-m {behavior}" or "--multipleAttributeBehavior {behavior}" --
 *       specifies the behavior that the tool should exhibit if multiple
 *       unique attributes are provided.  Allowed values include
 *       unique-within-each-attribute,
 *       unique-across-all-attributes-including-in-same-entry, and
 *       unique-across-all-attributes-except-in-same-entry.</LI>
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
  private static final String BEHAVIOR_UNIQUE_WITHIN_ATTR =
       "unique-within-each-attribute";



  /**
   * The unique attribute behavior value that indicates uniqueness should be
   * ensured across all attributes, and conflicts will not be allowed across
   * attributes in the same entry.
   */
  private static final String BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME =
       "unique-across-all-attributes-including-in-same-entry";



  /**
   * The unique attribute behavior value that indicates uniqueness should be
   * ensured across all attributes, except that conflicts will not be allowed
   * across attributes in the same entry.
   */
  private static final String BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME =
       "unique-across-all-attributes-except-in-same-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7904414224384249176L;



  // The number of entries examined so far.
  private final AtomicLong entriesExamined;

  // Indicates whether cross-attribute uniqueness conflicts should be allowed
  // in the same entry.
  private boolean allowConflictsInSameEntry;

  // Indicates whether uniqueness should be enforced across all attributes
  // rather than within each attribute.
  private boolean uniqueAcrossAttributes;

  // The argument used to specify the base DNs to use for searches.
  private DNArgument baseDNArgument;

  // The argument used to specify the search page size.
  private IntegerArgument pageSizeArgument;

  // The connection to use for finding unique attribute conflicts.
  private LDAPConnection findConflictsConnection;

  // A map with counts of unique attribute conflicts by attribute type.
  private final Map<String, AtomicLong> conflictCounts;

  // The names of the attributes for which to find uniqueness conflicts.
  private String[] attributes;

  // The set of base DNs to use for the searches.
  private String[] baseDNs;

  // The argument used to specify the attributes for which to find uniqueness
  // conflicts.
  private StringArgument attributeArgument;

  // The argument used to specify the behavior that should be exhibited if
  // multiple attributes are specified.
  private StringArgument multipleAttributeBehaviorArgument;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String... args)
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
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
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
  public IdentifyUniqueAttributeConflicts(final OutputStream outStream,
                                          final OutputStream errStream)
  {
    super(outStream, errStream);

    baseDNArgument = null;
    pageSizeArgument = null;
    attributeArgument = null;
    multipleAttributeBehaviorArgument = null;
    findConflictsConnection = null;
    allowConflictsInSameEntry = false;
    uniqueAcrossAttributes = false;
    attributes = null;
    baseDNs = null;

    entriesExamined = new AtomicLong(0L);
    conflictCounts = new TreeMap<String, AtomicLong>();
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  public String getToolName()
  {
    return "identify-unique-attribute-conflicts";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
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
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Override()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
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
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    String description = "The search base DN(s) to use to find entries with " +
         "attributes for which to find uniqueness conflicts.  At least one " +
         "base DN must be specified.";
    baseDNArgument = new DNArgument('b', "baseDN", true, 0, "{dn}",
         description);
    parser.addArgument(baseDNArgument);

    description = "The attribute(s) for which to find missing references.  " +
         "At least one attribute must be specified, and each attribute " +
         "must be indexed for equality searches and have values which are DNs.";
    attributeArgument = new StringArgument('A', "attribute", true, 0, "{attr}",
         description);
    parser.addArgument(attributeArgument);

    description = "Indicates the behavior to exhibit if multiple unique " +
         "attributes are provided.  Allowed values are '" +
         BEHAVIOR_UNIQUE_WITHIN_ATTR + "' (indicates that each value only " +
         "needs to be unique within its own attribute type), '" +
         BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME + "' (indicates that " +
         "each value needs to be unique across all of the specified " +
         "attributes), and '" + BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME +
         "' (indicates each value needs to be unique across all of the " +
         "specified attributes, except that multiple attributes in the same " +
         "entry are allowed to share the same value).";
    final LinkedHashSet<String> allowedValues = new LinkedHashSet<String>(3);
    allowedValues.add(BEHAVIOR_UNIQUE_WITHIN_ATTR);
    allowedValues.add(BEHAVIOR_UNIQUE_ACROSS_ATTRS_INCLUDING_SAME);
    allowedValues.add(BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME);
    multipleAttributeBehaviorArgument = new StringArgument('m',
         "multipleAttributeBehavior", false, 1, "{behavior}", description,
         allowedValues, BEHAVIOR_UNIQUE_WITHIN_ATTR);
    parser.addArgument(multipleAttributeBehaviorArgument);

    description = "The maximum number of entries to retrieve at a time when " +
         "attempting to find entries with references to other entries.  This " +
         "requires that the authenticated user have permission to use the " +
         "simple paged results control, but it can avoid problems with the " +
         "server sending entries too quickly for the client to handle.  By " +
         "default, the simple paged results control will not be used.";
    pageSizeArgument =
         new IntegerArgument('z', "simplePageSize", false, 1, "{num}",
              description, 1, Integer.MAX_VALUE);
    parser.addArgument(pageSizeArgument);
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
        allowConflictsInSameEntry = false;
      }
      else if (multiAttrBehavior.equalsIgnoreCase(
           BEHAVIOR_UNIQUE_ACROSS_ATTRS_EXCEPT_SAME))
      {
        uniqueAcrossAttributes = true;
        allowConflictsInSameEntry = true;
      }
      else
      {
        uniqueAcrossAttributes = false;
        allowConflictsInSameEntry = true;
      }
    }
    else
    {
      uniqueAcrossAttributes = false;
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
    final LDAPConnection findUniqueAttributesConnection;
    try
    {
      findUniqueAttributesConnection = getConnection();
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
        findConflictsConnection = getConnection();
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
      final Filter filter;
      if (attributes.length == 1)
      {
        filter = Filter.createPresenceFilter(attributes[0]);
        conflictCounts.put(attributes[0], new AtomicLong(0L));
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


      // Iterate across all of the search base DNs and perform searches to find
      // unique attributes.
      for (final String baseDN : baseDNs)
      {
        ASN1OctetString cookie = null;
        do
        {
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
            searchResult = findUniqueAttributesConnection.search(searchRequest);
          }
          catch (final LDAPSearchException lse)
          {
            Debug.debugException(lse);
            searchResult = lse.getSearchResult();
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


      // See if there were any missing references found.
      boolean conflictFound = false;
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

      if (conflictFound)
      {
        return ResultCode.CONSTRAINT_VIOLATION;
      }
      else
      {
        out("No unique attribute conflicts were found.");
        return ResultCode.SUCCESS;
      }
    }
    finally
    {
      findUniqueAttributesConnection.close();

      if (findConflictsConnection != null)
      {
        findConflictsConnection.close();
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
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<String[],String>(1);

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
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
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
            final Filter filter;
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

baseDNLoop:
            for (final String baseDN : baseDNs)
            {
              SearchResult searchResult;
              try
              {
                searchResult = findConflictsConnection.search(baseDN,
                     SearchScope.SUB, DereferencePolicy.NEVER, 2, 0, false,
                     filter, "1.1");
              }
              catch (final LDAPSearchException lse)
              {
                Debug.debugException(lse);
                searchResult = lse.getSearchResult();
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
   * Indicates that the provided search result reference has been returned by
   * the server and may be processed by this search result listener.
   *
   * @param  searchReference  The search result reference that has been returned
   *                          by the server.
   */
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    // No implementation is required.  This tool will not follow referrals.
  }
}
