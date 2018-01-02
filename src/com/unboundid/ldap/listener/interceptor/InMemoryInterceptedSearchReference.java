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



import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that can be used in the course of processing a
 * search request via the {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface InMemoryInterceptedSearchReference
       extends InMemoryInterceptedResult
{
  /**
   * Retrieves the search request that is being processed.  If the request was
   * altered between the time it was received from the client and the time it
   * was actually processed by the in-memory directory server, then this will be
   * the most recently altered version.
   *
   * @return  The search request that was processed.
   */
  ReadOnlySearchRequest getRequest();



  /**
   * Retrieves the search result reference to be returned to the client.
   *
   * @return  The search result reference to be returned to the client.
   */
  SearchResultReference getSearchReference();



  /**
   * Replaces the search result reference to be returned to the client.  It may
   * be {@code null} if the reference should be suppressed rather than being
   * returned to the client.
   *
   * @param  reference  The search result reference to be returned to the
   *                    client.  It may be {@code null} if the reference should
   *                    be suppressed rather than being returned to the client.
   */
  void setSearchReference(SearchResultReference reference);
}
