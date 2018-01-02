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



import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.SearchRequest;
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
public interface InMemoryInterceptedSearchRequest
       extends InMemoryInterceptedRequest
{
  /**
   * Retrieves the search request to be processed.
   *
   * @return  The search request to be processed.
   */
  ReadOnlySearchRequest getRequest();



  /**
   * Replaces the search request to be processed.
   *
   * @param  searchRequest  The search request that should be processed
   *                        instead of the one that was originally received
   *                        from the client.  It must not be {@code null}.
   */
  void setRequest(SearchRequest searchRequest);



  /**
   * Sends the provided search result entry to the client.  It will be processed
   * by the {@link InMemoryOperationInterceptor#processSearchEntry} method of
   * all registered operation interceptors.
   *
   * @param  entry  The search result entry to be returned to the client.  It
   *                must not be {@code null}.  If the provided entry is a
   *                {@code SearchResultEntry}, then it may optionally include
   *                one or more controls to provide to the client.  If it is any
   *                other type of {@code Entry}, then it will not include any
   *                controls.
   *
   * @throws  LDAPException  If a problem is encountered while trying to send
   *                         the search result entry.
   */
  void sendSearchEntry(Entry entry)
       throws LDAPException;



  /**
   * Sends the provided search result reference to the client.  It will be
   * processed by the
   * {@link InMemoryOperationInterceptor#processSearchReference} method of all
   * registered operation interceptors.
   *
   * @param  reference  The search result reference to be returned to the
   *                    client.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem is encountered while trying to send
   *                         the search result reference.
   */
  void sendSearchReference(SearchResultReference reference)
       throws LDAPException;
}
