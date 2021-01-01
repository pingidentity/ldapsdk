/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a mechanism for client-side entry sorting.  Sorting may
 * be based on attributes contained in the entry, and may also be based on the
 * hierarchical location of the entry in the DIT.  The sorting may be applied
 * to any collection of entries, including the entries included in a
 * {@link SearchResult} object.
 * <BR><BR>
 * This class provides a client-side alternative to the use of the
 * {@link com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl}.
 * Client-side sorting is most appropriate for small result sets, as it requires
 * all entries to be held in memory at the same time.  It is a good alternative
 * to server-side sorting when the overhead of sorting should be distributed
 * across client systems rather than on the server, and in cases in which the
 * target directory server does not support the use of the server-side sort
 * request control.
 * <BR><BR>
 * For best results, a {@link Schema} object may be used to provide an
 * indication as to which matching rules should be used to perform the ordering.
 * If no {@code Schema} object is provided, then all ordering will be performed
 * using case-ignore string matching.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example may be used to obtain a sorted set of search result
 * entries, ordered first by sn and then by givenName, without consideration for
 * hierarchy:
 * <PRE>
 * SearchResult searchResult = connection.search("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("sn", "Smith"));
 *
 * EntrySorter entrySorter = new EntrySorter(false,
 *      new SortKey("sn"), new SortKey("givenName"));
 * SortedSet&lt;Entry&gt; sortedEntries =
 *     entrySorter.sort(searchResult.getSearchEntries());
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EntrySorter
       implements Comparator<Entry>, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7606107105238612142L;



  // Indicates whether entries should be sorted based on hierarchy.
  private final boolean sortByHierarchy;

  // The set of sort keys for attribute-level sorting.
  @NotNull private final List<SortKey> sortKeys;

  // The schema to use to make the comparison, if available.
  @Nullable private final Schema schema;



  /**
   * Creates a new entry sorter that will sort entries based only on hierarchy.
   * Superior entries (that is, entries closer to the root of the DIT) will be
   * ordered before subordinate entries.  Entries below the same parent will be
   * sorted lexicographically based on their normalized DNs.
   */
  public EntrySorter()
  {
    this(true, null, Collections.<SortKey>emptyList());
  }



  /**
   * Creates a new entry sorter with the provided information.
   *
   * @param  sortByHierarchy  Indicates whether entries should be sorted
   *                          hierarchically, such that superior entries will
   *                          be ordered before subordinate entries.
   * @param  sortKeys         A list of sort keys that define the order in which
   *                          attributes should be compared.  It may be empty
   *                          (but never {@code null}) if sorting should be done
   *                          only based on hierarchy.
   */
  public EntrySorter(final boolean sortByHierarchy,
                     @NotNull final SortKey... sortKeys)
  {
    this(sortByHierarchy, null, Arrays.asList(sortKeys));
  }



  /**
   * Creates a new entry sorter with the provided information.
   *
   * @param  sortByHierarchy  Indicates whether entries should be sorted
   *                          hierarchically, such that superior entries will
   *                          be ordered before subordinate entries.
   * @param  schema           The schema to use to make the determination.  It
   *                          may be {@code null} if no schema is available.
   * @param  sortKeys         A list of sort keys that define the order in which
   *                          attributes should be compared.  It may be empty
   *                          (but never {@code null}) if sorting should be done
   *                          only based on hierarchy.
   */
  public EntrySorter(final boolean sortByHierarchy,
                     @Nullable final Schema schema,
                     @NotNull final SortKey... sortKeys)
  {
    this(sortByHierarchy, schema, Arrays.asList(sortKeys));
  }



  /**
   * Creates a new entry sorter with the provided information.
   *
   * @param  sortByHierarchy  Indicates whether entries should be sorted
   *                          hierarchically, such that superior entries will
   *                          be ordered before subordinate entries.
   * @param  sortKeys         A list of sort keys that define the order in which
   *                          attributes should be compared.  It may be empty or
   *                          {@code null} if sorting should be done only based
   *                          on hierarchy.
   */
  public EntrySorter(final boolean sortByHierarchy,
                     @Nullable final List<SortKey> sortKeys)
  {
    this(sortByHierarchy, null, sortKeys);
  }



  /**
   * Creates a new entry sorter with the provided information.
   *
   * @param  sortByHierarchy  Indicates whether entries should be sorted
   *                          hierarchically, such that superior entries will
   *                          be ordered before subordinate entries.
   * @param  schema           The schema to use to make the determination.  It
   *                          may be {@code null} if no schema is available.
   * @param  sortKeys         A list of sort keys that define the order in which
   *                          attributes should be compared.  It may be empty or
   *                          {@code null} if sorting should be done only based
   *                          on hierarchy.
   */
  public EntrySorter(final boolean sortByHierarchy,
                     @Nullable final Schema schema,
                     @Nullable final List<SortKey> sortKeys)
  {
    this.sortByHierarchy = sortByHierarchy;
    this.schema          = schema;

    if (sortKeys == null)
    {
      this.sortKeys = Collections.emptyList();
    }
    else
    {
      this.sortKeys = Collections.unmodifiableList(new ArrayList<>(sortKeys));
    }
  }



  /**
   * Sorts the provided collection of entries according to the criteria defined
   * in this entry sorter.
   *
   * @param  entries  The collection of entries to be sorted.
   *
   * @return  A sorted set, ordered in accordance with this entry sorter.
   */
  @NotNull()
  public SortedSet<Entry> sort(
              @NotNull final Collection<? extends Entry> entries)
  {
    final TreeSet<Entry> entrySet = new TreeSet<>(this);
    entrySet.addAll(entries);
    return entrySet;
  }



  /**
   * Compares the provided entries to determine the order in which they should
   * be placed in a sorted list.
   *
   * @param  e1  The first entry to be compared.
   * @param  e2  The second entry to be compared.
   *
   * @return  A negative value if the first entry should be ordered before the
   *          second, a positive value if the first entry should be ordered
   *          after the second, or zero if the entries should have an equivalent
   *          order.
   */
  @Override()
  public int compare(@NotNull final Entry e1, @NotNull final Entry e2)
  {
    DN parsedDN1 = null;
    DN parsedDN2 = null;

    if (sortByHierarchy)
    {
      try
      {
        parsedDN1 = e1.getParsedDN();
        parsedDN2 = e2.getParsedDN();

        if (parsedDN1.isAncestorOf(parsedDN2, false))
        {
          return -1;
        }
        else if (parsedDN2.isAncestorOf(parsedDN1, false))
        {
          return 1;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }

    for (final SortKey k : sortKeys)
    {
      final String attrName = k.getAttributeName();
      final Attribute a1 = e1.getAttribute(attrName);
      final Attribute a2 = e2.getAttribute(attrName);

      if ((a1 == null) || (! a1.hasValue()))
      {
        if ((a2 == null) || (! a2.hasValue()))
        {
          // Neither entry has the attribute.  Continue on with the next
          // attribute.
          continue;
        }
        else
        {
          // The first entry does not have the attribute but the second does.
          // The first entry should be ordered after the second.
          return 1;
        }
      }
      else
      {
        if ((a2 == null) || (! a2.hasValue()))
        {
          // The first entry has the attribute but the second does not.  The
          // first entry should be ordered before the second.
          return -1;
        }
      }


      final MatchingRule matchingRule = MatchingRule.selectOrderingMatchingRule(
           attrName, k.getMatchingRuleID(), schema);
      if (k.reverseOrder())
      {
        // Find the largest value for each attribute, and pick the larger of the
        // two.
        ASN1OctetString v1 = null;
        for (final ASN1OctetString s : a1.getRawValues())
        {
          if (v1 == null)
          {
            v1 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v1) > 0)
              {
                v1 = s;
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
            }
          }
        }

        ASN1OctetString v2 = null;
        for (final ASN1OctetString s : a2.getRawValues())
        {
          if (v2 == null)
          {
            v2 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v2) > 0)
              {
                v2 = s;
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
            }
          }
        }

        try
        {
          final int value = matchingRule.compareValues(v2, v1);
          if (value != 0)
          {
            return value;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }
      }
      else
      {
        // Find the smallest value for each attribute, and pick the larger of
        // the two.
        ASN1OctetString v1 = null;
        for (final ASN1OctetString s : a1.getRawValues())
        {
          if (v1 == null)
          {
            v1 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v1) < 0)
              {
                v1 = s;
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
            }
          }
        }

        ASN1OctetString v2 = null;
        for (final ASN1OctetString s : a2.getRawValues())
        {
          if (v2 == null)
          {
            v2 = s;
          }
          else
          {
            try
            {
              if (matchingRule.compareValues(s, v2) < 0)
              {
                v2 = s;
              }
            }
            catch (final LDAPException le)
            {
              Debug.debugException(le);
            }
          }
        }

        try
        {
          final int value = matchingRule.compareValues(v1, v2);
          if (value != 0)
          {
            return value;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }
      }
    }


    // If we've gotten here, then there is no difference in hierarchy or
    // sort attributes.  Compare the DNs as a last resort.
    try
    {
      if (parsedDN1 == null)
      {
        parsedDN1 = e1.getParsedDN();
      }

      if (parsedDN2 == null)
      {
        parsedDN2 = e2.getParsedDN();
      }

      return parsedDN1.compareTo(parsedDN2);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      final String lowerDN1 = StaticUtils.toLowerCase(e1.getDN());
      final String lowerDN2 = StaticUtils.toLowerCase(e2.getDN());
      return lowerDN1.compareTo(lowerDN2);
    }
  }



  /**
   * Retrieves a hash code for this entry sorter.
   *
   * @return  A hash code for this entry sorter.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = 0;

    if (sortByHierarchy)
    {
      hashCode++;
    }

    for (final SortKey k : sortKeys)
    {
      if (k.reverseOrder())
      {
        hashCode *= -31;
      }
      else
      {
        hashCode *= 31;
      }

      hashCode += StaticUtils.toLowerCase(k.getAttributeName()).hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this entry sorter.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this entry sorter,
   *          or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof EntrySorter))
    {
      return false;
    }

    final EntrySorter s = (EntrySorter) o;
    if (sortByHierarchy != s.sortByHierarchy)
    {
      return false;
    }

    return sortKeys.equals(s.sortKeys);
  }



  /**
   * Retrieves a string representation of this entry sorter.
   *
   * @return  A string representation of this entry sorter.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this entry sorter to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EntrySorter(sortByHierarchy=");
    buffer.append(sortByHierarchy);
    buffer.append(", sortKeys={");

    final Iterator<SortKey> iterator = sortKeys.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
