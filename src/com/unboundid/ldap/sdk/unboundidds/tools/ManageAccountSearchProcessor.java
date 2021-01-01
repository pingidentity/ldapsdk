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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.IntegerArgument;



/**
 * This class provides a mechanism for ensuring that manage-account arguments
 * used to identify which entries to process by filter or user ID are handled
 * properly.  It will perform searches to identify matching entries, and those
 * entries will be provided to a {@link ManageAccountProcessor} to ensure that
 * the appropriate password policy state operation is invoked for them.
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
final class ManageAccountSearchProcessor
{
  // A queue used to hold the filters for the searches to process.
  @Nullable private final LinkedBlockingQueue<Filter> filterQueue;

  // A handle to the manage-account tool instance with which this search
  // processor is associated.
  @NotNull private final ManageAccount manageAccount;

  // A handle to the manage-account processor that will be used to process the
  // identified search result entries.
  @NotNull private final ManageAccountProcessor manageAccountProcessor;

  // The active search operation for this processor, if only a single search
  // thread is to be used.
  @Nullable private volatile ManageAccountSearchOperation activeSearchOperation;

  // The maximum page size to use when performing searches.
  private final int simplePageSize;

  // The connection pool to use to communicate with the server.
  @NotNull private final LDAPConnectionPool pool;

  // The list of processor threads that have been created.
  @NotNull private final List<ManageAccountSearchProcessorThread>
       searchProcessorThreads;

  // The base DN to use for search requests.
  @NotNull private final String baseDN;

  // The user ID attribute.
  @NotNull private final String userIDAttribute;



  /**
   * Creates a new instance of this manage-account search processor with the
   * provided information.
   *
   * @param  manageAccount           A handle to the manage-account tool
   *                                 instance with which this search processor
   *                                 is associated.
   * @param  manageAccountProcessor  A handle to the manage-account processor
   *                                 that will be used to process the identified
   *                                 search result entries.
   * @param  pool                    The connection pool to use to communicate
   *                                 with the server.
   */
  ManageAccountSearchProcessor(@NotNull final ManageAccount manageAccount,
       @NotNull final ManageAccountProcessor manageAccountProcessor,
       @NotNull final LDAPConnectionPool pool)
  {
    this.manageAccount = manageAccount;
    this.manageAccountProcessor = manageAccountProcessor;
    this.pool = pool;

    final ArgumentParser parser = manageAccount.getArgumentParser();

    activeSearchOperation = null;

    baseDN = parser.getDNArgument(
         ManageAccount.ARG_BASE_DN).getValue().toString();
    userIDAttribute = parser.getStringArgument(
         ManageAccount.ARG_USER_ID_ATTRIBUTE).getValue();

    final IntegerArgument simplePageSizeArg =
         parser.getIntegerArgument(ManageAccount.ARG_SIMPLE_PAGE_SIZE);
    if (simplePageSizeArg.isPresent())
    {
      simplePageSize = simplePageSizeArg.getValue();
    }
    else
    {
      simplePageSize = -1;
    }

    final int numSearchThreads = parser.getIntegerArgument(
         ManageAccount.ARG_NUM_SEARCH_THREADS).getValue();
    if (numSearchThreads > 1)
    {
      filterQueue = new LinkedBlockingQueue<>(100);
      searchProcessorThreads = new ArrayList<>(numSearchThreads);
      for (int i=1; i <= numSearchThreads; i++)
      {
        final ManageAccountSearchProcessorThread t =
             new ManageAccountSearchProcessorThread(i, this);
        t.start();
        searchProcessorThreads.add(t);
      }
    }
    else
    {
      filterQueue = null;
      searchProcessorThreads = Collections.emptyList();
    }
  }



  /**
   * Ensures that a search operation is processed with the given filter.  This
   * will either process the search operation immediately in the current thread
   * (if a single manage-account search thread is configured), or will enqueue
   * the filter to be processed by another thread.
   *
   * @param  filter  The filter to use for the search request to process.
   */
  void processFilter(@NotNull final Filter filter)
  {
    if (filterQueue == null)
    {
      try
      {
        activeSearchOperation = new ManageAccountSearchOperation(manageAccount,
             manageAccountProcessor, pool, baseDN, filter, simplePageSize);
        activeSearchOperation.doSearch();
      }
      finally
      {
        activeSearchOperation = null;
      }
    }
    else
    {
      while (! manageAccount.cancelRequested())
      {
        try
        {
          if (filterQueue.offer(filter, 100L, TimeUnit.MILLISECONDS))
          {
            return;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          if (e instanceof InterruptedException)
          {
            Thread.currentThread().interrupt();
          }
        }
      }
    }
  }



  /**
   * Ensures that a search operation is processed with the given filter.  This
   * will either process the search operation immediately in the current thread
   * (if a single manage-account search thread is configured), or will enqueue
   * the filter to be processed by another thread.
   *
   * @param  filter  The string representation of the filter to use for the
   *                 search request to process.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         search filter.
   */
  void processFilter(@NotNull final String filter)
       throws LDAPException
  {
    processFilter(Filter.create(filter));
  }



  /**
   * Ensures that a search operation is processed with a filter constructed for
   * the given user ID.  This will either process the search operation
   * immediately in the current thread (if a single manage-account search thread
   * is configured), or will enqueue the filter to be processed by another
   * thread.
   *
   * @param  userID  The user ID for which toi search.
   */
  void processUserID(@NotNull final String userID)
  {
    processFilter(Filter.createEqualityFilter(userIDAttribute, userID));
  }



  /**
   * Retrieves the next search operation to be processed.  This should only be
   * called by {@link ManageAccountSearchProcessorThread} instances.
   *
   * @return  The next search request to be processed, or {@code null} if no
   *          more processing should be performed.
   */
  @Nullable()
  ManageAccountSearchOperation getSearchOperation()
  {
    // If the tool has been interrupted, then return null to signal that the
    // thread should exit.
    if (manageAccount.cancelRequested())
    {
      return null;
    }


    // Get the next filter to process.  Get it without waiting if we can, but
    // check for cancel and end of input regularly.
    Filter filter = filterQueue.poll();
    while (filter == null)
    {
      if (manageAccount.cancelRequested())
      {
        return null;
      }

      if (manageAccount.allFiltersProvided())
      {
        filter = filterQueue.poll();
        if (filter == null)
        {
          return null;
        }
        else
        {
          break;
        }
      }

      try
      {
        filter = filterQueue.poll(100L, TimeUnit.MILLISECONDS);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
        }
      }
    }

    return new ManageAccountSearchOperation(manageAccount,
         manageAccountProcessor, pool, baseDN, filter, simplePageSize);
  }



  /**
   * Cancels all search operations currently in progress.
   */
  void cancelSearches()
  {
    final ManageAccountSearchOperation o = activeSearchOperation;
    if (o != null)
    {
      o.cancelSearch();
    }

    for (final ManageAccountSearchProcessorThread t : searchProcessorThreads)
    {
      t.cancelSearch();
    }
  }



  /**
   * Blocks until all search operations have been processed.
   */
  void waitForCompletion()
  {
    // If we don't have a filter queue, then all of the operations are processed
    // synchronously and we know that we're done.
    if (filterQueue == null)
    {
      return;
    }

    while (true)
    {
      // If the manage-account tool has been interrupted, then we can declare
      // the processing complete.  We don't care about what's in the queue or
      // what the processor threads are doing.
      if (manageAccount.cancelRequested())
      {
        return;
      }


      // If all of the filters have been provided, then we still need to wait
      // until the queue is empty and all of the processor threads have
      // completed.
      if (manageAccount.allFiltersProvided() && (filterQueue.peek() == null))
      {
        for (final ManageAccountSearchProcessorThread t :
             searchProcessorThreads)
        {
          try
          {
            t.join();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);

            if (e instanceof InterruptedException)
            {
              Thread.currentThread().interrupt();
            }
          }
        }

        return;
      }

      try
      {
        Thread.sleep(10L);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }
}
