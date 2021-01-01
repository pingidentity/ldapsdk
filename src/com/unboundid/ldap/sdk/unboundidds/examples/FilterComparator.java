/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.Serializable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.TreeSet;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a comparator that may be used to define a relative order
 * for search filters.  The filter order will be based first on the filter type
 * (in the following order:   AND, OR, NOT, equality, substring,
 * greater-or-equal, less-or-equal, presence, approximate match, extensible
 * match), then based on the attribute name, and then by the assertion value.
 * For AND and OR filters, with all other things equal, a filter with fewer
 * components will be ordered before one with more components.  For a substring
 * filter with all other things equal, then a filter missing a substring element
 * will be ordered before one with that element, and one with fewer subAny
 * elements will be ordered before one with more subAny elements.  For an
 * extensible match filter with all other things being equal, a filter without
 * an element will be ordered before one with that element.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FilterComparator
       implements Comparator<Filter>, Serializable
{
  /**
   * The singleton instance of this comparator.
   */
  @NotNull private static final FilterComparator INSTANCE =
       new FilterComparator();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7637416445464620770L;



  /**
   * Creates a new instance of this filter comparator.
   */
  private FilterComparator()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this filter comparator.
   *
   * @return  The singleton instance of this filter comparator.
   */
  @NotNull()
  public static FilterComparator getInstance()
  {
    return INSTANCE;
  }



  /**
   * Determines a relative order for the provided filter objects.
   *
   * @param  f1  The first filter for which to make the determination.
   *             It must not be {@code null}
   * @param  f2  The second filter for which to make the determination.
   *             It must not be {@code null}
   *
   * @return  A negative value if the first filter should be ordered before the
   *          second, a positive value if the first filter should be ordered
   *          after the second, or zero if there is no difference in their
   *          relative orders.
   */
  @Override()
  public int compare(@NotNull final Filter f1, @NotNull final Filter f2)
  {
    if (f1 == f2)
    {
      return 0;
    }

    Validator.ensureNotNull(f1, f2);

    final byte type1 = f1.getFilterType();
    final byte type2 = f2.getFilterType();

    if (type1 != type2)
    {
      return ((type1 & 0x1F) - (type2 & 0x1F));
    }

    final String name1 = StaticUtils.toLowerCase(f1.getAttributeName());
    final String name2 = StaticUtils.toLowerCase(f2.getAttributeName());
    if ((name1 != null) && (name2 != null))
    {
      final int cmpValue = name1.compareTo(name2);
      if (cmpValue != 0)
      {
        return cmpValue;
      }
    }

    final byte[] value1 = f1.getAssertionValueBytes();
    if (value1 != null)
    {
      final byte[] value2 = f2.getAssertionValueBytes();
      final int cmpValue = compare(value1, value2);
      if (cmpValue != 0)
      {
        return cmpValue;
      }
    }

    switch (type1)
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        return compareANDOrOR(f1, f2);

      case Filter.FILTER_TYPE_NOT:
        return compare(f1.getNOTComponent(), f2.getNOTComponent());

      case Filter.FILTER_TYPE_PRESENCE:
      case Filter.FILTER_TYPE_EQUALITY:
      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        // The necessary processing for these types has already been done.
        return 0;

      case Filter.FILTER_TYPE_SUBSTRING:
        return compareSubstring(f1, f2);

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        return compareExtensible(f1, f2);

      default:
        // This should never happen.
        return 0;
    }
  }



  /**
   * Performs a comparison of the contents of AND or OR filters.
   *
   * @param  f1  The first filter for which to make the determination.
   * @param  f2  The second filter for which to make the determination.
   *
   * @return  A negative value if the first filter should be ordered before the
   *          second, a positive value if the first filter should be ordered
   *          after the second, or zero if there is no difference in their
   *          relative orders.
   */
  private static int compareANDOrOR(@NotNull final Filter f1,
                                    @NotNull final Filter f2)
  {
    final TreeSet<Filter> set1 = new TreeSet<>(INSTANCE);
    final TreeSet<Filter> set2 = new TreeSet<>(INSTANCE);

    set1.addAll(Arrays.asList(f1.getComponents()));
    set2.addAll(Arrays.asList(f2.getComponents()));

    final Iterator<Filter> iterator1 = set1.iterator();
    final Iterator<Filter> iterator2 = set2.iterator();
    while (true)
    {
      final Filter comp1;
      if (iterator1.hasNext())
      {
        comp1 = iterator1.next();
      }
      else if (iterator2.hasNext())
      {
        return -1;
      }
      else
      {
        return 0;
      }

      final Filter comp2;
      if (iterator2.hasNext())
      {
        comp2 = iterator2.next();
      }
      else
      {
        return 1;
      }

      final int compValue = INSTANCE.compare(comp1, comp2);
      if (compValue != 0)
      {
        return compValue;
      }
    }
  }



  /**
   * Performs a comparison of the contents of substring filters.
   *
   * @param  f1  The first filter for which to make the determination.
   * @param  f2  The second filter for which to make the determination.
   *
   * @return  A negative value if the first filter should be ordered before the
   *          second, a positive value if the first filter should be ordered
   *          after the second, or zero if there is no difference in their
   *          relative orders.
   */
  private static int compareSubstring(@NotNull final Filter f1,
                                      @NotNull final Filter f2)
  {
    final byte[] sI1 = f1.getSubInitialBytes();
    final byte[] sI2 = f2.getSubInitialBytes();
    if (sI1 == null)
    {
      if (sI2 != null)
      {
        return -1;
      }
    }
    else if (sI2 == null)
    {
      return 1;
    }
    else
    {
      final int cmpValue = compare(sI1, sI2);
      if (cmpValue != 0)
      {
        return cmpValue;
      }
    }

    final byte[][] sA1 = f1.getSubAnyBytes();
    final byte[][] sA2 = f2.getSubAnyBytes();
    if (sA1.length == 0)
    {
      if (sA2.length > 0)
      {
        return -1;
      }
    }
    else if (sA2.length == 0)
    {
      return 1;
    }
    else
    {
      final int minLength = Math.min(sA1.length, sA2.length);
      for (int i=0; i < minLength; i++)
      {
        final int cmpValue = compare(sA1[i], sA2[i]);
        if (cmpValue != 0)
        {
          return cmpValue;
        }
      }

      if (sA1.length < sA2.length)
      {
        return -1;
      }
      else if (sA2.length < sA1.length)
      {
        return 1;
      }
    }

    final byte[] sF1 = f1.getSubFinalBytes();
    final byte[] sF2 = f2.getSubFinalBytes();
    if (sF1 == null)
    {
      if (sF2 != null)
      {
        return -1;
      }
      else
      {
        return 0;
      }
    }
    else if (sF2 == null)
    {
      return 1;
    }
    else
    {
      return compare(sF1, sF2);
    }
  }



  /**
   * Performs a comparison of the contents of substring filters.
   *
   * @param  f1  The first filter for which to make the determination.
   * @param  f2  The second filter for which to make the determination.
   *
   * @return  A negative value if the first filter should be ordered before the
   *          second, a positive value if the first filter should be ordered
   *          after the second, or zero if there is no difference in their
   *          relative orders.
   */
  private static int compareExtensible(@NotNull final Filter f1,
                                       @NotNull final Filter f2)
  {
    final String name1 = f1.getAttributeName();
    final String name2 = f2.getAttributeName();
    if (name1 == null)
    {
      if (name2 != null)
      {
        return -1;
      }
    }
    else if (name2 == null)
    {
      return 1;
    }

    final String mr1 = f1.getMatchingRuleID();
    final String mr2 = f2.getMatchingRuleID();
    if (mr1 == null)
    {
      if (mr2 != null)
      {
        return -1;
      }
    }
    else if (mr2 == null)
    {
      return 1;
    }
    else
    {
      final int cmpValue = mr1.compareTo(mr2);
      if (cmpValue != 0)
      {
        return cmpValue;
      }
    }

    if (f1.getDNAttributes())
    {
      if (f2.getDNAttributes())
      {
        return 0;
      }
      else
      {
        return 1;
      }
    }
    else if (f2.getDNAttributes())
    {
      return -1;
    }
    else
    {
      return 0;
    }
  }



  /**
   * Performs a comparison of the contents of the provided byte arrays.
   *
   * @param  a1  The first array to be compared.
   * @param  a2  The second array to be compared.
   *
   * @return  An integer value denoting the comparison value.
   */
  private static int compare(@NotNull final byte[] a1,
                             @NotNull final byte[] a2)
  {
    final int length = Math.min(a1.length, a2.length);

    for (int i=0; i < length; i++)
    {
      final int b1 = 0xFF & a1[i];
      final int b2 = 0xFF & a2[i];
      if (b1 != b2)
      {
        return b1 - b2;
      }
    }

    return (a1.length - a2.length);
  }



  /**
   * Retrieves a hash code for this filter comparator.
   *
   * @return  A hash code for this filter comparator.
   */
  @Override()
  public int hashCode()
  {
    return 0;
  }



  /**
   * Indicates whether the provided object is equal to this filter comparator.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this filter
   *          comparator, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    return ((o != null) && (o instanceof FilterComparator));
  }
}
