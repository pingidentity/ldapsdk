/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used in the course of
 * processing a search operation via the {@link InMemoryOperationInterceptor}
 * API.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
final class InterceptedSearchEntry
      extends InterceptedOperation
      implements InMemoryInterceptedSearchEntry
{
  // The search request for this operation.
  private final ReadOnlySearchRequest searchRequest;

  // The search result entry to be processed.
  private SearchResultEntry entry;



  /**
   * Creates a new instance of this search entry object with the provided
   * information.
   *
   * @param  op               The search operation being processed.
   * @param  entry            The search result entry to be processed.
   * @param  requestControls  The set of controls included in the request.
   */
  InterceptedSearchEntry(final InterceptedSearchOperation op,
                         final SearchResultEntryProtocolOp entry,
                         final Control... requestControls)
  {
    super(op);

    searchRequest = op.getRequest();
    this.entry = entry.toSearchResultEntry(requestControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReadOnlySearchRequest getRequest()
  {
    return searchRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SearchResultEntry getSearchEntry()
  {
    return entry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setSearchEntry(final Entry entry)
  {
    if (entry == null)
    {
      this.entry = null;
    }
    else if (entry instanceof SearchResultEntry)
    {
      this.entry = (SearchResultEntry) entry;
    }
    else
    {
      this.entry = new SearchResultEntry(entry);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InterceptedSearchEntry(");
    appendCommonToString(buffer);
    buffer.append(", request=");
    buffer.append(searchRequest);
    buffer.append(", entry=");
    buffer.append(entry);
    buffer.append(')');
  }
}
