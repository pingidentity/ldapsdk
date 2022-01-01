/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.IntermediateResponseListener;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StreamDirectoryValuesExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StreamDirectoryValuesIntermediateResponse;
import com.unboundid.util.DNFileReader;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a thread that can be used to retrieve the DNs to examine
 * for a server used in conjunction with the {@link LDAPDiff} tool.  The DNs
 * may be obtained from a file, using the
 * {@link StreamDirectoryValuesExtendedRequest}, or by performing a search.
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
 */
final class LDAPDiffDNDumper
      extends Thread
      implements SearchResultListener, IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6528470329756007939L;



  // A reference indicating whether any error was encountered during stream
  // directory values intermediate response processing.
  @NotNull private final AtomicReference<Boolean>
       streamValuesIntermediateResponseErrorEncounteredRef;

  // A reference to an exception that was caught during processing.
  @NotNull private final AtomicReference<LDAPException> exceptionRef;

  // Indicates whether to only report entries that exist on one server but not
  // the other.
  private final boolean missingOnly;

  // Indicates whether to operate in quiet mode.
  private final boolean quiet;

  // The base DN for entries to include.
  @NotNull private final DN baseDN;

  // A file containing the DNs for entries to include.
  @Nullable private final File dnFile;

  // A filter to identify the entries to include.
  @NotNull private final Filter filter;

  // The set of base DNs for branches that should be excluded.
  @NotNull private final List<DN> excludeBranches;

  // The last progress value that was displayed.
  private long lastProgressValue;

  // A connection pool to use to communicate with the LDAP server.
  @NotNull private final LDAPConnectionPool connectionPool;

  // A reference to the associated ldap-diff tool.
  @NotNull private final LDAPDiff ldapDiff;

  // The schema to use during processing.
  @Nullable private final Schema schema;

  // The scope for entries to include.
  @NotNull private final SearchScope scope;

  // The set to update with the compact representations of the DNs that were
  // retrieved.
  @NotNull private final TreeSet<LDAPDiffCompactDN> dnSet;



  /**
   * Creates a new DN dumper thread with the provided information.
   *
   * @param  ldapDiff         A reference to the associated ldap-diff tool.  It
   *                          must not be {@code null}.
   * @param  name             The name to use for this thread.  it must not be
   *                          {@code null}.
   * @param  dnFile           The path to a file from which the DNs should be
   *                          read.  This may be {@code null} if the DNs should
   *                          be obtained over LDAP.
   * @param  connectionPool   The connection pool to use when retrieving the DNs
   *                          over LDAP.  It must not be {@code null} and must
   *                          be established.
   * @param  baseDN           The base DN for entries to include.  It must not
   *                          be {@code null}.
   * @param  scope            The scope for entries to include.  It must not be
   *                          {@code null}.
   * @param  excludeBranches  The set of base DNs for branches that should be
   *                          excluded.  It must not be {@code null} but may be
   *                          empty.
   * @param  filter           The filter to use to identify entries to include.
   *                          It must not be {@code null}.
   * @param  schema           The schema to use during processing.  It may be
   *                          {@code null} if no schema is available.
   * @param  missingOnly      Indicates whether to only report entries that
   *                          exist on one server but not the other.
   * @param  quiet            Indicates whether to operate in quiet mode, in
   *                          which no progress output is generated.
   * @param  dnSet            The set that should be updated with the compact
   *                          representations of the DNs that were retrieved.
   *                          It must not be {@code null}, and all access to
   *                          this set must be synchronized to ensure thread
   *                          safety.
   */
  LDAPDiffDNDumper(@NotNull final LDAPDiff ldapDiff,
                   @NotNull final String name,
                   @Nullable final File dnFile,
                   @NotNull final LDAPConnectionPool connectionPool,
                   @NotNull final DN baseDN,
                   @NotNull final SearchScope scope,
                   @NotNull final List<DN> excludeBranches,
                   @NotNull final Filter filter,
                   @Nullable final Schema schema,
                   final boolean missingOnly,
                   final boolean quiet,
                   @NotNull final TreeSet<LDAPDiffCompactDN> dnSet)
  {
    super(name);
    setDaemon(true);

    this.ldapDiff = ldapDiff;
    this.dnFile = dnFile;
    this.connectionPool = connectionPool;
    this.baseDN = baseDN;
    this.scope = scope;
    this.excludeBranches = excludeBranches;
    this.filter = filter;
    this.schema = schema;
    this.missingOnly = missingOnly;
    this.quiet = quiet;
    this.dnSet = dnSet;

    lastProgressValue = 0L;
    streamValuesIntermediateResponseErrorEncounteredRef =
         new AtomicReference<>();
    exceptionRef = new AtomicReference<>();
  }



  /**
   * Retrieves an exception that was caught during processing, if any.
   *
   * @return  An exception that was caught during processing, or {@code null} if
   *          no exception was caught.
   */
  @Nullable()
  LDAPException getProcessingException()
  {
    return exceptionRef.get();
  }



  /**
   * Performs the appropriate processing for this thread.
   */
  @Override()
  public void run()
  {
    // If a DN file was specified, then retrieve the entries from it.
    if (dnFile != null)
    {
      readDNsFromFile();
    }
    else
    {
      readDNsFromLDAP();
    }
  }



  /**
   * Reads the entry DNs from a file.
   */
  private void readDNsFromFile()
  {
    try
    {
      final DNFileReader dnFileReader = new DNFileReader(dnFile);
      while (true)
      {
        final DN dn;
        try
        {
          dn = dnFileReader.readDN();
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          exceptionRef.set(e);
          return;
        }

        if (dn == null)
        {
          return;
        }

        if (dn.matchesBaseAndScope(baseDN, scope) &&
             (! isWithinExcludeBranch(dn)))
        {
          synchronized (dnSet)
          {
            final LDAPDiffCompactDN compactDN =
                 new LDAPDiffCompactDN(dn, baseDN);
            if (missingOnly && dnSet.contains(compactDN))
            {
              dnSet.remove(compactDN);
            }
            else
            {
              dnSet.add(new LDAPDiffCompactDN(dn, baseDN));
              if ((! quiet) && (dnSet.size() != lastProgressValue) &&
                   ((dnSet.size() % 1_000) == 0))
              {
                lastProgressValue = dnSet.size();
                ldapDiff.wrapOut(0, LDAPDiff.WRAP_COLUMN,
                     INFO_LDAP_DIFF_DN_DUMPER_PROGRESS.get(dnSet.size()));
              }
            }
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      exceptionRef.set(new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_LDAP_DIFF_DN_DUMPER_ERROR_READING_FROM_FILE.get(
                dnFile.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e));
    }
  }



  /**
   * Retrieves the entry DNs from LDAP.
   */
  private void readDNsFromLDAP()
  {
    // First, see if we can use the stream directory values extended operation
    // to obtain the DNs.
    if (readDNsWithStreamValues())
    {
      return;
    }


    // If we've gotten here, then we couldn't use the stream directory values
    // operation.  In that case, just perform a search to retrieve the entries.
    SearchResult searchResult;
    try
    {
      final SearchRequest searchRequest = new SearchRequest(this,
           baseDN.toString(), scope, DereferencePolicy.NEVER, 0, 0, false,
           filter, SearchRequest.NO_ATTRIBUTES);
      searchResult = connectionPool.search(searchRequest);
    }
    catch (final LDAPSearchException e)
    {
      Debug.debugException(e);
      searchResult = e.getSearchResult();
    }

    switch (searchResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
        // This indicates that no problem was encountered during searching.
        break;

      case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
        // This indicates that the search base entry does not exist. This is
        // also not a problem.
        break;

      case ResultCode.REFERRAL_INT_VALUE:
        // This indicates that the server wants us to look elsewhere for the
        // entries.  The ldap-diff tool does not support referrals, so this is
        // an error.
        exceptionRef.compareAndSet(null,
             new LDAPException(ResultCode.LOCAL_ERROR,
                  ERR_LDAP_DIFF_SEARCH_FAILED_WITH_REFERRAL.get(
                       Arrays.toString(searchResult.getReferralURLs()))));
        break;

      default:
        // The search failed for some other reason.
        exceptionRef.compareAndSet(null,
             new LDAPException(searchResult.getResultCode(),
                  ERR_LDAP_DIFF_SEARCH_FAILED.get(String.valueOf(
                       searchResult))));
    }
  }



  /**
   * Attempts to use the stream directory values extended operation to read the
   * DNs of the applicable entries from the server.  This extended operation
   * will be used only if all the following conditions are true:
   * <OL>
   *   <LI>The filter is "(objectClass=*)".</LI>
   *   <LI>The server's root DSE advertises support for the extended
   *       operation.</LI>
   *   <LI>The base DN is at or below one of the naming contexts listed in the
   *       root DSE.</LI>
   * </OL>
   *
   * @return  {@code true} if the stream directory values operation was
   *          attempted and completed successfully, or {@code false} if the
   *          operation was not attempted or if an error was encountered during
   *          processing.
   */
  private boolean readDNsWithStreamValues()
  {
    try
    {
      // Make sure that there is an appropriate filter and scope for using the
      // extended operation.
      if (! filter.equals(Filter.createPresenceFilter("objectClass")))
      {
        return false;
      }


      // Get the root DSE and make sure that it advertises support for the
      // operation and that it lists the base DN as one of the naming contexts.
      final RootDSE rootDSE = connectionPool.getRootDSE();
      if (rootDSE == null)
      {
        return false;
      }

      if (! rootDSE.supportsExtendedOperation(
           StreamDirectoryValuesExtendedRequest.
                STREAM_DIRECTORY_VALUES_REQUEST_OID))
      {
        return false;
      }

      boolean withinNamingContext = false;
      final String[] namingContextDNs = rootDSE.getNamingContextDNs();
      if (namingContextDNs != null)
      {
        for (final String namingContextDN : namingContextDNs)
        {
          if (baseDN.isDescendantOf(new DN(namingContextDN, schema), true))
          {
            withinNamingContext = true;
            break;
          }
        }
      }

      if (! withinNamingContext)
      {
        return false;
      }


      // If we've gotten here, then we're going to try the operation.  Issue
      // the request.
      final StreamDirectoryValuesExtendedRequest streamValuesRequest =
           new StreamDirectoryValuesExtendedRequest(baseDN.toString(), scope,
                false, null, 1_000);
      streamValuesRequest.setIntermediateResponseListener(this);

      final ExtendedResult streamValuesResult =
           connectionPool.processExtendedOperation(streamValuesRequest);
      if (streamValuesResult.getResultCode() == ResultCode.SUCCESS)
      {
        return (streamValuesIntermediateResponseErrorEncounteredRef.get() ==
             null);
      }
      else
      {
        if (Debug.debugEnabled())
        {
          Debug.debug(Level.WARNING, DebugType.LDAP,
               "The server returned non-success result " + streamValuesResult +
                    " in response to stream directory values extended " +
                    "request " + streamValuesRequest + ".  Falling back to " +
                    "searching for entries to examine.");
        }

        return false;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Indicates whether the provided DN is beneath any of the configured exclude
   * branches.
   *
   * @param  dn  The DN for which to make the determination.  It must not be
   *             {@code null}.
   *
   * @return  {@code true} if the provided DN is within any of the exclude
   *          branches, or {@code false} if not.
   */
  private boolean isWithinExcludeBranch(@NotNull final DN dn)
  {
    for (final DN excludeBranch : excludeBranches)
    {
      if (dn.isDescendantOf(excludeBranch, true))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    try
    {
      final DN dn = searchEntry.getParsedDN();
      if (dn.matchesBaseAndScope(baseDN, scope) &&
           (! isWithinExcludeBranch(dn)))
      {
        final LDAPDiffCompactDN compactDN = new LDAPDiffCompactDN(dn, baseDN);
        synchronized (dnSet)
        {
          if (missingOnly && dnSet.contains(compactDN))
          {
            dnSet.remove(compactDN);
          }
          else
          {
            dnSet.add(compactDN);
            if ((! quiet) && (dnSet.size() != lastProgressValue) &&
                 ((dnSet.size() % 1_000) == 0))
            {
              lastProgressValue = dnSet.size();
              ldapDiff.wrapOut(0, LDAPDiff.WRAP_COLUMN,
                   INFO_LDAP_DIFF_DN_DUMPER_PROGRESS.get(dnSet.size()));
            }
          }
        }
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      exceptionRef.compareAndSet(null,
           new LDAPException(e.getResultCode(),
                ERR_LDAP_DIFF_SEARCH_ENTRY_ERROR.get(searchEntry.getDN(),
                     StaticUtils.getExceptionMessage(e)),
                e));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    exceptionRef.compareAndSet(null,
         new LDAPException(ResultCode.LOCAL_ERROR,
              ERR_LDAP_DIFF_REFERENCE_ENCOUNTERED.get(
                   String.valueOf(searchReference))));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void intermediateResponseReturned(
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    // If we encountered an error in an earlier invocation of this method, then
    // there's no point in processing this one.
    if (streamValuesIntermediateResponseErrorEncounteredRef.get() != null)
    {
      return;
    }


    try
    {
      // Parse the intermediate response as a stream directory values
      // intermediate response.  If this fails (either because the response is
      // malformed or because it's some other type of intermediate repsonse that
      // we didn't expect and don't support in this class), then set an error
      // flag and bail.
      final StreamDirectoryValuesIntermediateResponse streamValuesIR =
           new StreamDirectoryValuesIntermediateResponse(intermediateResponse);


      // Get a list of the values contained in this intermediate response and
      // convert them to compact DNs.
      final List<ASN1OctetString> valueOctetStrings =
           streamValuesIR.getValues();
      final List<LDAPDiffCompactDN> compactDNs =
           new ArrayList<>(valueOctetStrings.size());
      for (final ASN1OctetString valueOctetString : valueOctetStrings)
      {
        final DN dn = new DN(valueOctetString.stringValue(), schema);
        if (dn.matchesBaseAndScope(baseDN, scope) &&
             (! isWithinExcludeBranch(dn)))
        {
          compactDNs.add(new LDAPDiffCompactDN(dn, baseDN));
        }
      }


      // Add all the compact DNs to the DN set.  Make sure to do this in a
      // synchronized block to avoid thread safety issues.
      synchronized (dnSet)
      {
        for (final LDAPDiffCompactDN compactDN : compactDNs)
        {
          if (missingOnly && dnSet.contains(compactDN))
          {
            dnSet.remove(compactDN);
          }
          else
          {
            dnSet.add(compactDN);
            if ((! quiet) && (dnSet.size() != lastProgressValue) &&
                 ((dnSet.size() % 1_000) == 0))
            {
              lastProgressValue = dnSet.size();
              ldapDiff.wrapOut(0, LDAPDiff.WRAP_COLUMN,
                   INFO_LDAP_DIFF_DN_DUMPER_PROGRESS.get(dnSet.size()));
            }
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      streamValuesIntermediateResponseErrorEncounteredRef.set(Boolean.TRUE);
    }
  }
}
