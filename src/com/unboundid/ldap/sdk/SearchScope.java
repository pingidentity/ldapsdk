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
import java.util.HashMap;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a data type for search scope values.  Clients should
 * generally use one of the {@code BASE}, {@code ONE}, {@code SUB}, or
 * {@code SUBORDINATE_SUBTREE} values, although it is possible to create a new
 * scope with a specified integer value if necessary using the
 * {@link #valueOf(int)} method.  The following search scope values are defined:
 * <UL>
 *   <LI>{@code BASE} -- Indicates that only the entry specified by the base DN
 *       should be considered.</LI>
 *   <LI>{@code ONE} -- Indicates that only entries that are immediate
 *       subordinates of the entry specified by the base DN (but not the base
 *       entry itself) should be considered.</LI>
 *   <LI>{@code SUB} -- Indicates that the base entry itself and any subordinate
 *       entries (to any depth) should be considered.</LI>
 *   <LI>{@code SUBORDINATE_SUBTREE} -- Indicates that any subordinate entries
 *       (to any depth) below the entry specified by the base DN should be
 *       considered, but the base entry itself should not be considered, as
 *       described in draft-sermersheim-ldap-subordinate-scope.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchScope
       implements Serializable
{
  /**
   * The integer value for the "base" search scope.
   */
  public static final int BASE_INT_VALUE = 0;



  /**
   * A predefined baseObject scope value, which indicates that only the entry
   * specified by the base DN should be considered.
   */
  @NotNull public static final SearchScope BASE =
       new SearchScope("BASE", BASE_INT_VALUE);



  /**
   * The integer value for the "one" search scope.
   */
  public static final int ONE_INT_VALUE = 1;



  /**
   * A predefined singleLevel scope value, which indicates that only entries
   * that are immediate subordinates of the entry specified by the base DN (but
   * not the base entry itself) should be considered.
   */
  @NotNull public static final SearchScope ONE =
       new SearchScope("ONE", ONE_INT_VALUE);



  /**
   * The integer value for the "sub" search scope.
   */
  public static final int SUB_INT_VALUE = 2;



  /**
   * A predefined wholeSubtree scope value, which indicates that the base entry
   * itself and any subordinate entries (to any depth) should be considered.
   */
  @NotNull public static final SearchScope SUB =
       new SearchScope("SUB", SUB_INT_VALUE);



  /**
   * The integer value for the "subordinate subtree" search scope.
   */
  public static final int SUBORDINATE_SUBTREE_INT_VALUE = 3;



  /**
   * A predefined subordinateSubtree scope value, which indicates that any
   * subordinate entries (to any depth) below the entry specified by the base DN
   * should be considered, but the base entry itself should not be considered.
   */
  @NotNull public static final SearchScope SUBORDINATE_SUBTREE =
       new SearchScope("SUBORDINATE_SUBTREE", SUBORDINATE_SUBTREE_INT_VALUE);



  /**
   * The set of search scope objects created with undefined int values.
   */
  @NotNull private static final HashMap<Integer,SearchScope> UNDEFINED_SCOPES =
       new HashMap<>(StaticUtils.computeMapCapacity(5));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5381929718445793181L;



  // The integer value for this search scope.
  private final int intValue;

  // The name to use for this search scope.
  @NotNull private final String name;



  /**
   * Creates a new search scope with the specified integer value.
   *
   * @param  intValue  The integer value to use for this search scope.
   */
  private SearchScope(final int intValue)
  {
    this.intValue = intValue;

    name = String.valueOf(intValue);
  }



  /**
   * Creates a new search scope with the specified name and integer value.
   *
   * @param  name      The name to use for this search scope.
   * @param  intValue  The integer value to use for this search scope.
   */
  private SearchScope(@NotNull final String name, final int intValue)
  {
    this.name     = name;
    this.intValue = intValue;
  }



  /**
   * Retrieves the name for this search scope.
   *
   * @return  The name for this search scope.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this search scope.
   *
   * @return  The integer value for this search scope.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the search scope with the specified integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   search scope.
   *
   * @return  The search scope with the specified integer value, or a new search
   *          scope if the provided value does not match any of the predefined
   *          scopes.
   */
  @NotNull()
  public static SearchScope valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return BASE;
      case 1:
        return ONE;
      case 2:
        return SUB;
      case 3:
        return SUBORDINATE_SUBTREE;
      default:
        synchronized (UNDEFINED_SCOPES)
        {
          SearchScope s = UNDEFINED_SCOPES.get(intValue);
          if (s == null)
          {
            s = new SearchScope(intValue);
            UNDEFINED_SCOPES.put(intValue, s);
          }

          return s;
        }
    }
  }



  /**
   * Retrieves the predefined search scope with the specified integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   search scope.
   *
   * @return  The search scope with the specified integer value, or {@code null}
   *          if the provided integer value does not represent a defined scope.
   */
  @Nullable()
  public static SearchScope definedValueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return BASE;
      case 1:
        return ONE;
      case 2:
        return SUB;
      case 3:
        return SUBORDINATE_SUBTREE;
      default:
        return null;
    }
  }



  /**
   * Retrieves an array of all search scopes defined in the LDAP SDK.
   *
   * @return  An array of all search scopes defined in the LDAP SDK.
   */
  @NotNull()
  public static SearchScope[] values()
  {
    return new SearchScope[]
    {
      BASE,
      ONE,
      SUB,
      SUBORDINATE_SUBTREE
    };
  }



  /**
   * The hash code for this search scope.
   *
   * @return  The hash code for this search scope.
   */
  @Override()
  public int hashCode()
  {
    return intValue;
  }



  /**
   * Indicates whether the provided object is equal to this search scope.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a search scope that is
   *          equal to this search scope, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }
    else if (o == this)
    {
      return true;
    }
    else if (o instanceof SearchScope)
    {
      return (intValue == ((SearchScope) o).intValue);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this search scope.
   *
   * @return  A string representation of this search scope.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
