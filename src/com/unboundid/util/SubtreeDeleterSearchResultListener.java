/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.util.Arrays;
import java.util.SortedSet;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a search result listener implementation that will collect
 * the DNs of the entries returned in a sorted set.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SubtreeDeleterSearchResultListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6828026542462924962L;



  // A reference to the first exception caught during processing.
  @NotNull private final AtomicReference<LDAPException> firstException;

  // The base DN for the associated search request.
  @NotNull private final DN searchBaseDN;

  // The filter for the associated search request.
  @NotNull private final Filter searchFilter;

  // A set to be updated with the DNs of the entries returned from the search.
  @NotNull private final SortedSet<DN> dnSet;



  /**
   * Creates a new instance of this search result listener that will add items
   * to the provided set.
   *
   * @param  searchBaseDN  The base DN for the associated search request.  It
   *                       must not be {@code null}.
   * @param  searchFilter  The filter for the associated search request.  It
   *                       must not be {@code null}.
   * @param  dnSet         A sorted set that will be updated with the DNs of the
   *                       entries that are returned from the associated search.
   *                       It must not be {@code null}, and must be updatable.
   */
  SubtreeDeleterSearchResultListener(@NotNull final DN searchBaseDN,
                                     @NotNull final Filter searchFilter,
                                     @NotNull final SortedSet<DN> dnSet)
  {
    this.searchBaseDN = searchBaseDN;
    this.searchFilter = searchFilter;
    this.dnSet = dnSet;

    firstException = new AtomicReference<>();
  }



  /**
   * Retrieves the first exception that was caught during processing.
   *
   * @return  The first exception that was caught during processing, or
   *          {@code null} if no exception was caught during processing.
   */
  @Nullable()
  LDAPException getFirstException()
  {
    return firstException.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    try
    {
      dnSet.add(searchEntry.getParsedDN());
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      firstException.compareAndSet(null, e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    if (firstException.get() == null)
    {
      final String urlsString;
      final String[] referralURLs = searchReference.getReferralURLs();
      if (referralURLs.length == 1)
      {
        urlsString = referralURLs[0];
      }
      else
      {
        urlsString = Arrays.toString(referralURLs);
      }

      firstException.compareAndSet(null,
           new LDAPException(ResultCode.REFERRAL,
                ERR_SUBTREE_DELETER_SEARCH_LISTENER_REFERENCE_RETURNED.get(
                     urlsString, String.valueOf(searchBaseDN),
                     String.valueOf(searchFilter))));
    }
  }
}
