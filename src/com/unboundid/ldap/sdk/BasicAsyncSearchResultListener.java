/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a basic implementation of the
 * {@link AsyncSearchResultListener} interface that will merely set the
 * result object to a local variable that can be accessed through a getter
 * method.  It provides a listener that may be easily used when processing
 * an asynchronous search operation using the {@link AsyncRequestID} as a
 * {@code java.util.concurrent.Future} object.
 * <BR><BR>
 * Note that this class stores all entries and references returned by the
 * associated search in memory so that they can be retrieved in lists.  This may
 * not be suitable for searches that have the potential return a large number
 * of entries.  For such searches, an alternate
 * {@link AsyncSearchResultListener} implementation may be needed, or it may be
 * more appropriate to use an {@link LDAPEntrySource} object for the search.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BasicAsyncSearchResultListener
       implements AsyncSearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2289128360755244209L;



  // The list of search result entries that have been returned.
  private final List<SearchResultEntry> entryList;

  // The list of search result references that have been returned.
  private final List<SearchResultReference> referenceList;

  // The search result that has been received for the associated search
  // operation.
  private volatile SearchResult searchResult;



  /**
   * Creates a new instance of this class for use in processing a single search
   * operation.  A single basic async search result listener object may not be
   * used for multiple operations.
   */
  public BasicAsyncSearchResultListener()
  {
    searchResult  = null;
    entryList     = new ArrayList<SearchResultEntry>(5);
    referenceList = new ArrayList<SearchResultReference>(5);
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    entryList.add(searchEntry);
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    referenceList.add(searchReference);
  }




  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void searchResultReceived(final AsyncRequestID requestID,
                                    final SearchResult searchResult)
  {
    this.searchResult = searchResult;
  }



  /**
   * Retrieves the result that has been received for the associated asynchronous
   * search operation, if it has been received.
   *
   * @return  The result that has been received for the associated asynchronous
   *          search operation, or {@code null} if no response has been received
   *          yet.
   */
  public SearchResult getSearchResult()
  {
    return searchResult;
  }



  /**
   * Retrieves a list of the entries returned for the search operation.  This
   * should only be called after the operation has completed and a
   * non-{@code null} search result object is available, because it may not be
   * safe to access the contents of the list if it may be altered while the
   * search is still in progress.
   *
   * @return  A list of the entries returned for the search operation.
   */
  public List<SearchResultEntry> getSearchEntries()
  {
    return Collections.unmodifiableList(entryList);
  }



  /**
   * Retrieves a list of the references returned for the search operation.  This
   * should only be called after the operation has completed and a
   * non-{@code null} search result object is available, because it may not be
   * safe to access the contents of the list if it may be altered while the
   * search is still in progress.
   *
   * @return  A list of the references returned for the search operation.
   */
  public List<SearchResultReference> getSearchReferences()
  {
    return Collections.unmodifiableList(referenceList);
  }
}
