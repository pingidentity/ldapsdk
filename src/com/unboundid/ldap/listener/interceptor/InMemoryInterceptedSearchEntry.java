/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that can be used in the course of processing a
 * search request via the {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface InMemoryInterceptedSearchEntry
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
  @NotNull()
  ReadOnlySearchRequest getRequest();



  /**
   * Retrieves the search result entry to be returned to the client.
   *
   * @return  The search result entry to be returned to the client.
   */
  @Nullable()
  SearchResultEntry getSearchEntry();



  /**
   * Replaces the search result entry to be returned to the client.  It may be
   * {@code null} if the entry should be suppressed rather than being returned
   * to the client.  If the provided entry is a {@code SearchResultEntry}, then
   * it may optionally include one or more controls to provide to the client.
   * If it is any other type of {@code Entry}, then it will not include any
   * controls.
   *
   * @param  entry  The search result entry to be returned to the client.  It
   *                may be {@code null} if the entry should be suppressed rather
   *                than being returned to the client.  If the provided entry is
   *                a {@code SearchResultEntry}, then it may optionally include
   *                one or more controls to provide to the client.  If it is any
   *                other type of {@code Entry}, then it will not include any
   *                controls.
   */
  void setSearchEntry(@Nullable Entry entry);
}
