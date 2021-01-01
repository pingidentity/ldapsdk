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
package com.unboundid.ldap.sdk.transformations;



import java.io.Serializable;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry transformation that will
 * return {@code null} for any entry that matches (or alternately, does not
 * match) a given set of criteria and should therefore be excluded from the data
 * set.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExcludeEntryTransformation
       implements EntryTransformation, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 103514669827637043L;



  // An optional counter that will be incremented for each entry that has been
  // excluded.
  @Nullable private final AtomicLong excludedCount;

  // Indicates whether we need to check entries against the filter.
  private final boolean allEntriesMatchFilter;

  // Indicates whether we need to check entries against the scope.
  private final boolean allEntriesAreInScope;

  // Indicates whether to exclude entries that match the criteria, or to exclude
  // entries that do no not match the criteria.
  private final boolean excludeMatching;

  // The base DN to use to identify entries to exclude.
  @NotNull private final DN baseDN;

  // The filter to use to identify entries to exclude.
  @NotNull private final Filter filter;

  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The scope to use to identify entries to exclude.
  @NotNull private final SearchScope scope;



  /**
   * Creates a new exclude entry transformation with the provided information.
   *
   * @param  schema           The schema to use in processing.  It may be
   *                          {@code null} if a default standard schema should
   *                          be used.
   * @param  baseDN           The base DN to use to identify which entries to
   *                          suppress.  If this is {@code null}, it will be
   *                          assumed to be the null DN.
   * @param  scope            The scope to use to identify which entries to
   *                          suppress.  If this is {@code null}, it will be
   *                          assumed to be {@link SearchScope#SUB}.
   * @param  filter           An optional filter to use to identify which
   *                          entries to suppress.  If this is {@code null},
   *                          then a default LDAP true filter (which will match
   *                          any entry) will be used.
   * @param  excludeMatching  Indicates whether to exclude entries that match
   *                          the criteria (if {@code true}) or to exclude
   *                          entries that do not match the criteria (if
   *                          {@code false}).
   * @param  excludedCount    An optional counter that will be incremented for
   *                          each entry that is excluded.
   */
  public ExcludeEntryTransformation(@Nullable final Schema schema,
                                    @Nullable final DN baseDN,
                                    @Nullable final SearchScope scope,
                                    @Nullable final Filter filter,
                                    final boolean excludeMatching,
                                    @Nullable final AtomicLong excludedCount)
  {
    this.excludeMatching = excludeMatching;
    this.excludedCount = excludedCount;


    // If a schema was provided, then use it.  Otherwise, use the default
    // standard schema.
    Schema s = schema;
    if (s == null)
    {
      try
      {
        s = Schema.getDefaultStandardSchema();
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
      }
    }
    this.schema = s;


    // If a base DN was provided, then use it.  Otherwise, use the null DN.
    if (baseDN == null)
    {
      this.baseDN = DN.NULL_DN;
    }
    else
    {
      this.baseDN = baseDN;
    }


    // If a scope was provided, then use it.  Otherwise, use a subtree scope.
    if (scope == null)
    {
      this.scope = SearchScope.SUB;
    }
    else
    {
      this.scope = scope;
    }
    allEntriesAreInScope =
         (this.baseDN.isNullDN() && (this.scope == SearchScope.SUB));


    // If a filter was provided, then use it.  Otherwise, use an LDAP true
    // filter.
    if (filter == null)
    {
      this.filter = Filter.createANDFilter();
      allEntriesMatchFilter = true;
    }
    else
    {
      this.filter = filter;
      if (filter.getFilterType() == Filter.FILTER_TYPE_AND)
      {
        allEntriesMatchFilter = (filter.getComponents().length == 0);
      }
      else
      {
        allEntriesMatchFilter = false;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry transformEntry(@NotNull final Entry e)
  {
    if (e == null)
    {
      return null;
    }


    // Determine whether the entry is within the configured scope.
    boolean matchesScope;
    try
    {
      matchesScope =
           (allEntriesAreInScope || e.matchesBaseAndScope(baseDN, scope));
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);

      // This should only happen if the entry has a malformed DN.  In that
      // case, we'll say that it doesn't match the scope.
      matchesScope = false;
    }


    // Determine whether the entry matches the suppression filter.
    boolean matchesFilter;
    try
    {
      matchesFilter = (allEntriesMatchFilter || filter.matchesEntry(e, schema));
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);

      // This should only happen if the filter is one that we can't process at
      // all or against the target entry.  In that case, we'll say that it
      // doesn't match the filter.
      matchesFilter = false;
    }


    if (matchesScope && matchesFilter)
    {
      if (excludeMatching)
      {
        if (excludedCount != null)
        {
          excludedCount.incrementAndGet();
        }
        return null;
      }
      else
      {
        return e;
      }
    }
    else
    {
      if (excludeMatching)
      {
        return e;
      }
      else
      {
        if (excludedCount != null)
        {
          excludedCount.incrementAndGet();
        }
        return null;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translate(@NotNull final Entry original,
                         final long firstLineNumber)
  {
    return transformEntry(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translateEntryToWrite(@NotNull final Entry original)
  {
    return transformEntry(original);
  }
}
