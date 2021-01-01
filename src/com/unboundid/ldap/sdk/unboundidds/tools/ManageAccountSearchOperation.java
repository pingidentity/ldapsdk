/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.AsyncSearchResultListener;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class performs the work needed to process a search operation as part of
 * manage-account processing.
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
final class ManageAccountSearchOperation
      implements AsyncSearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5568681845030018155L;



  // The async request ID for the search that is currently in progress.
  @Nullable private volatile AsyncRequestID asyncRequestID;

  // A counter used to keep track of the number of entries returned.
  @NotNull private final AtomicInteger entryCounter;

  // A counter used to keep track of the number of references returned.
  @NotNull private final AtomicInteger referenceCounter;

  // A map of the DNs that have already been processed.  This is used to ensure
  // that we don't attempt to perform duplicate processing for any entries in
  // the event that a problem is encountered while processing a search.
  @NotNull private final ConcurrentHashMap<DN,DN> dnsProcessed;

  // The page size to use for the simple paged results control, if appropriate.
  private final int simplePageSize;

  // The connection pool to use to communicate with the server.
  @NotNull private final LDAPConnectionPool pool;

  // A handle to the manage-account tool instance.
  @NotNull private final ManageAccount manageAccount;

  // A handle to the manage-account processor instance.
  @NotNull private final ManageAccountProcessor manageAccountProcessor;

  // The search request to process.
  @NotNull private final SearchRequest searchRequest;



  /**
   * Creates a new manage account search operation with the provided
   * information.
   *
   * @param  manageAccount           A handle to the manage-account tool
   *                                 instance.
   * @param  manageAccountProcessor  The manage-account processor that will be
   *                                 used to process entries identified by this
   *                                 search.
   * @param  pool                    The connection pool to use to communicate
   *                                 with the server.
   * @param  baseDN                  The base DN to use for the search.
   * @param  filter                  The filter to use for the search.
   * @param  simplePageSize          The simple page size to use for the search.
   */
  ManageAccountSearchOperation(@NotNull final ManageAccount manageAccount,
       @NotNull final ManageAccountProcessor manageAccountProcessor,
       @NotNull final LDAPConnectionPool pool,
       @NotNull final String baseDN,
       @NotNull final Filter filter,
       final int simplePageSize)
  {
    this.manageAccount = manageAccount;
    this.manageAccountProcessor = manageAccountProcessor;
    this.pool = pool;
    this.simplePageSize = simplePageSize;

    searchRequest = new SearchRequest(this, baseDN, SearchScope.SUB, filter,
         SearchRequest.NO_ATTRIBUTES);
    searchRequest.setResponseTimeoutMillis(3_600_000L);

    dnsProcessed = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(10));
    entryCounter = new AtomicInteger(0);
    referenceCounter = new AtomicInteger(0);
  }



  /**
   * Processes the search.  This will use an asynchronous operation so that the
   * search can be canceled, but this method will not return until the search
   * has completed or has been canceled.
   */
  void doSearch()
  {
    ASN1OctetString cookie = null;
    while (true)
    {
      if (simplePageSize > 0)
      {
        searchRequest.setControls(
             new SimplePagedResultsControl(simplePageSize, cookie, false));
      }

      final SearchResult searchResult = doSearchWithRetry();

      if (searchResult.getResultCode() != ResultCode.SUCCESS)
      {
        break;
      }

      if (simplePageSize <= 0)
      {
        break;
      }

      try
      {
        final SimplePagedResultsControl responseControl =
             SimplePagedResultsControl.get(searchResult);
        if (responseControl.moreResultsToReturn())
        {
          cookie = responseControl.getCookie();
        }
        else
        {
          break;
        }
      }
      catch (final Exception e)
      {
        manageAccountProcessor.handleMessage(
             ERR_MANAGE_ACCT_SEARCH_OP_ERROR_READING_PAGE_RESPONSE.get(
                  String.valueOf(searchResult),
                  String.valueOf(searchRequest.getFilter()),
                  StaticUtils.getExceptionMessage(e)),
             true);
      }
    }
  }



  /**
   * Processes the search operation with the potential for a retry if the search
   * fails in a manner that suggests that the connection may no longer be valid.
   *
   * @return  The result obtained from processing the search.
   */
  @NotNull()
  private SearchResult doSearchWithRetry()
  {
    // Even if the search is being processed in multiple pages, there shouldn't
    // be any overlap between pages, and we only need to remember the entries
    // returned within a given page.  So we can clear the set of DNs processed
    // because
    dnsProcessed.clear();
    entryCounter.set(0);
    referenceCounter.set(0);

    // Get a connection to use to process the operation.
    LDAPConnection conn;
    try
    {
      conn = pool.getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      final String message =
           ERR_MANAGE_ACCT_SEARCH_OP_CANNOT_GET_CONNECTION.get(
                String.valueOf(searchRequest),
                StaticUtils.getExceptionMessage(le));
      manageAccountProcessor.handleMessage(message, true);
      return new SearchResult(searchRequest.getLastMessageID(),
           ResultCode.CONNECT_ERROR, message, null, null, entryCounter.get(),
           referenceCounter.get(), null);
    }

    boolean alreadyReleased = false;
    boolean releaseAsDefunct = true;
    try
    {
      // Send an asynchronous request to the server and wait for the response.
      LDAPResult result = null;
      try
      {
        asyncRequestID = conn.asyncSearch(searchRequest);
        result = asyncRequestID.get();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        result = le.toLDAPResult();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      finally
      {
        asyncRequestID = null;
      }


      // If we have a non-null result with a result code that indicates that
      // the connection is still usable, then we're done and we can release
      // the connection for re-use.
      if ((result != null) && (result.getResultCode().isConnectionUsable()))
      {
        releaseAsDefunct = false;
        if (result.getResultCode() == ResultCode.SUCCESS)
        {
          if (simplePageSize > 0)
          {
            manageAccountProcessor.handleMessage(
                 INFO_MANAGE_ACCT_SEARCH_OP_SUCCESSFUL_PAGE.get(
                      String.valueOf(searchRequest.getFilter()),
                      entryCounter.get()),
                 false);
          }
          else
          {
            manageAccountProcessor.handleMessage(
                 INFO_MANAGE_ACCT_SEARCH_OP_SUCCESSFUL_FULL.get(
                      String.valueOf(searchRequest.getFilter()),
                      entryCounter.get()),
                 false);
          }
        }
        else
        {
          manageAccountProcessor.handleMessage(
               ERR_MANAGE_ACCT_SEARCH_OP_FAILED_NO_RETRY.get(
                    String.valueOf(searchRequest.getFilter()),
                    result.getResultCode(), result.getDiagnosticMessage()),
               true);
        }

        if (result instanceof SearchResult)
        {
          return (SearchResult) result;
        }
        else
        {
          return new SearchResult(result.getMessageID(), result.getResultCode(),
               result.getDiagnosticMessage(), result.getMatchedDN(),
               result.getReferralURLs(), entryCounter.get(),
               referenceCounter.get(), result.getResponseControls());
        }
      }


      // If we've gotten here, then something went very wrong with the first
      // attempt.  Try to replace the connection with a newly-created one.
      entryCounter.set(0);
      referenceCounter.set(0);
      try
      {
        alreadyReleased = true;
        conn = pool.replaceDefunctConnection(conn);
        alreadyReleased = false;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        final String message =
             ERR_MANAGE_ACCT_SEARCH_OP_CANNOT_GET_CONNECTION.get(
                  String.valueOf(searchRequest),
                  StaticUtils.getExceptionMessage(le));
        manageAccountProcessor.handleMessage(message, true);
        return new SearchResult(searchRequest.getLastMessageID(),
             ResultCode.CONNECT_ERROR, message, null, null, entryCounter.get(),
             referenceCounter.get(), null);
      }


      // Make a second attempt at processing the operation.
      try
      {
        asyncRequestID = conn.asyncSearch(searchRequest);
        result = asyncRequestID.get();
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        result = le.toLDAPResult();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        result = new SearchResult(searchRequest.getLastMessageID(),
             ResultCode.LOCAL_ERROR,
             ERR_MANAGE_ACCT_SEARCH_OP_EXCEPTION.get(
                  String.valueOf(searchRequest),
                  StaticUtils.getExceptionMessage(e)),
             null, null, entryCounter.get(), referenceCounter.get(), null);
      }
      finally
      {
        asyncRequestID = null;
      }

      if (result.getResultCode() == ResultCode.SUCCESS)
      {
        if (simplePageSize > 0)
        {
          manageAccountProcessor.handleMessage(
               INFO_MANAGE_ACCT_SEARCH_OP_SUCCESSFUL_PAGE.get(
                    String.valueOf(searchRequest.getFilter()),
                    entryCounter.get()),
               false);
        }
        else
        {
          manageAccountProcessor.handleMessage(
               INFO_MANAGE_ACCT_SEARCH_OP_SUCCESSFUL_FULL.get(
                    String.valueOf(searchRequest.getFilter()),
                    entryCounter.get()),
               false);
        }
      }
      else
      {
        manageAccountProcessor.handleMessage(
             ERR_MANAGE_ACCT_SEARCH_OP_FAILED_SECOND_ATTEMPT.get(
                  String.valueOf(searchRequest.getFilter()),
                  result.getResultCode(), result.getDiagnosticMessage()),
             true);
      }

      if (result.getResultCode().isConnectionUsable())
      {
        releaseAsDefunct = false;
      }

      if (result instanceof SearchResult)
      {
        return (SearchResult) result;
      }
      else
      {
        return new SearchResult(result.getMessageID(), result.getResultCode(),
             result.getDiagnosticMessage(), result.getMatchedDN(),
             result.getReferralURLs(), entryCounter.get(),
             referenceCounter.get(), result.getResponseControls());
      }
    }
    finally
    {
      if (! alreadyReleased)
      {
        if (releaseAsDefunct)
        {
          pool.releaseDefunctConnection(conn);
        }
        else
        {
          pool.releaseConnection(conn);
        }
      }
    }
  }



  /**
   * Cancels the search operation.
   */
  void cancelSearch()
  {
    if (asyncRequestID != null)
    {
      asyncRequestID.cancel(true);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    entryCounter.incrementAndGet();

    // Make sure we haven't already seen this entry.  We shouldn't get the same
    // entry multiple times in the course of processing a search, but if we got
    // a failure while processing the search, we might re-try it and get some of
    // the same entries back.
    DN parsedDN = null;
    try
    {
      parsedDN = searchEntry.getParsedDN();
      if (dnsProcessed.containsKey(parsedDN))
      {
        return;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    manageAccountProcessor.process(searchEntry.getDN());

    if (parsedDN != null)
    {
      dnsProcessed.put(parsedDN, parsedDN);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    referenceCounter.incrementAndGet();

    manageAccountProcessor.handleMessage(
         WARN_MANAGE_ACCT_SEARCH_OP_REFERRAL.get(
              String.valueOf(searchRequest.getFilter()),
              String.valueOf(searchReference)),
         true);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchResultReceived(@NotNull final AsyncRequestID requestID,
                                   @NotNull final SearchResult searchResult)
  {
    // No processing is required.  We'll get the result via AsyncRequestID.get.
  }
}
