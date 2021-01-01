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
import java.util.TreeSet;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for representing search filters in a
 * generic way.
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
 * <BR>
 * This includes:
 * <UL>
 *   <LI>Using a consistent order for AND and OR components.</LI>
 *   <LI>Converting all attribute names to lowercase.</LI>
 *   <LI>Replacing the assertion value with a "?" character for equality,
 *       greater-or-equal, less-or-equal, approximate match, and extensible
 *       match filters.</LI>
 *   <LI>Replacing all subInitial, subAny, and subFinal elements with "?"
 *       characters in substring filters.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenericFilter
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7875317078624475546L;



  // The hash code for this generic filter.
  private final int hashCode;

  // The string representation for this filter.
  @NotNull private final String filterString;



  /**
   * Creates a new generic filter from the provided search filter.
   *
   * @param  f  The filter to use to create a generic filter.
   */
  public GenericFilter(@NotNull final Filter f)
  {
    final StringBuilder b = new StringBuilder();
    b.append('(');

    switch (f.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
      case Filter.FILTER_TYPE_OR:
        appendComponents(f, b);
        break;

      case Filter.FILTER_TYPE_NOT:
        b.append('!');
        b.append(new GenericFilter(f.getNOTComponent()).toString());
        break;

      case Filter.FILTER_TYPE_EQUALITY:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append("=?");
        break;

      case Filter.FILTER_TYPE_SUBSTRING:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append('=');
        if (f.getRawSubInitialValue() != null)
        {
          b.append('?');
        }
        for (int i=0; i < f.getRawSubAnyValues().length; i++)
        {
          b.append("*?");
        }
        b.append('*');
        if (f.getRawSubFinalValue() != null)
        {
          b.append('?');
        }
        break;

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append(">=?");
        break;

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append("<=?");
        break;

      case Filter.FILTER_TYPE_PRESENCE:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append("=*");
        break;

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        b.append(StaticUtils.toLowerCase(f.getAttributeName()));
        b.append("~=?");
        break;

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        final String attrName = StaticUtils.toLowerCase(f.getAttributeName());
        final String mrID     = StaticUtils.toLowerCase(f.getMatchingRuleID());
        if (attrName != null)
        {
          b.append(attrName);
        }
        if (f.getDNAttributes())
        {
          b.append(":dn");
        }
        if (mrID != null)
        {
          b.append(':');
          b.append(mrID);
        }
        b.append(":=?");
        break;
    }

    b.append(')');

    filterString = b.toString();
    hashCode     = filterString.hashCode();
  }



  /**
   * Appends a string representation of the provided AND or OR filter to the
   * given buffer.
   *
   * @param  f  The filter for which to provide the string representation.
   * @param  b  The buffer to which to append the string representation.
   */
  private static void appendComponents(@NotNull final Filter f,
                                       @NotNull final StringBuilder b)
  {
    if (f.getFilterType() == Filter.FILTER_TYPE_AND)
    {
      b.append('&');
    }
    else
    {
      b.append('|');
    }

    final TreeSet<Filter> compSet =
         new TreeSet<>(FilterComparator.getInstance());
    compSet.addAll(Arrays.asList(f.getComponents()));
    for (final Filter fc : compSet)
    {
      b.append(new GenericFilter(fc).toString());
    }
  }



  /**
   * Retrieves a hash code for this generic filter.
   *
   * @return  A hash code for this generic filter.
   */
  @Override()
  public int hashCode()
  {
    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this generic filter.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} the provided object is equal to this generic filter,
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

    return ((o instanceof GenericFilter) &&
            filterString.equals(((GenericFilter) o).filterString));
  }



  /**
   * Retrieves a string representation of this generic filter.
   *
   * @return  A string representation of this generic filter.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return filterString;
  }
}
