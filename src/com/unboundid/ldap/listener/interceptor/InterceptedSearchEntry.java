/*
 * Copyright 2014-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2025 Ping Identity Corporation
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
 * Copyright (C) 2014-2025 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
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
  @NotNull private final ReadOnlySearchRequest searchRequest;

  // The search result entry to be processed.
  @Nullable private SearchResultEntry entry;



  /**
   * Creates a new instance of this search entry object with the provided
   * information.
   *
   * @param  op               The search operation being processed.
   * @param  entry            The search result entry to be processed.
   * @param  requestControls  The set of controls included in the request.
   */
  InterceptedSearchEntry(@NotNull final InterceptedSearchOperation op,
                         @NotNull final SearchResultEntryProtocolOp entry,
                         @Nullable final Control... requestControls)
  {
    super(op);

    searchRequest = op.getRequest();
    this.entry = entry.toSearchResultEntry(requestControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReadOnlySearchRequest getRequest()
  {
    return searchRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public SearchResultEntry getSearchEntry()
  {
    return entry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void setSearchEntry(@Nullable final Entry entry)
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
  public void toString(@NotNull final StringBuilder buffer)
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
