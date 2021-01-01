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
package com.unboundid.util;



import java.io.Serializable;
import java.util.Comparator;



/**
 * This class provides an implementation of a {@code Comparator} object that may
 * be used to iterate through values in what would normally be considered
 * reverse order.
 *
 * @param  <T>  The type of object to use with this comparator.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReverseComparator<T>
       implements Comparator<T>, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4615537960027681276L;



  // The comparator that will be used to make the underlying determination.
  @Nullable private final Comparator<T> baseComparator;



  /**
   * Creates a new comparator that will sort items in reverse order.  The
   * generic type for this class must implement the {@link Comparable}
   * interface.
   */
  public ReverseComparator()
  {
    baseComparator = null;
  }



  /**
   * Creates a new comparator that will sort items in the reverse order that
   * they would be normally sorted using the given comparator.
   *
   * @param  baseComparator  The base comparator that will be used to make the
   *                         determination.
   */
  public ReverseComparator(@NotNull final Comparator<T> baseComparator)
  {
    this.baseComparator = baseComparator;
  }



  /**
   * Compares the provided objects to determine their relative order in a
   * sorted list.
   *
   * @param  o1  The first object to compare.
   * @param  o2  The second object to compare.
   *
   * @return  A negative integer if the first object should be ordered before
   *          the second, a positive integer if the first object should be
   *          ordered after the second, or zero if there is no difference in
   *          their relative orders.
   */
  @SuppressWarnings("unchecked")
  @Override()
  public int compare(@NotNull final T o1, @NotNull final T o2)
  {
    final int baseValue;
    if (baseComparator == null)
    {
      baseValue = ((Comparable<? super T>) o1).compareTo(o2);
    }
    else
    {
      baseValue = baseComparator.compare(o1, o2);
    }

    if (baseValue < 0)
    {
      return 1;
    }
    else if (baseValue > 0)
    {
      return -1;
    }
    else
    {
      return 0;
    }
  }



  /**
   * Retrieves a hash code for this class.
   *
   * @return  A hash code for this class.
   */
  @Override()
  public int hashCode()
  {
    if (baseComparator == null)
    {
      return 0;
    }
    else
    {
      return baseComparator.hashCode();
    }
  }



  /**
   * Indicates whether the provided object may be considered equal to this
   * comparator.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this comparator, or {@code false} if not.
   */
  @Override()
  @SuppressWarnings("unchecked")
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

    if (! (o.getClass().equals(ReverseComparator.class)))
    {
      return false;
    }

    final ReverseComparator<T> c = (ReverseComparator<T>) o;
    if (baseComparator == null)
    {
      return (c.baseComparator == null);
    }
    else
    {
      return baseComparator.equals(c.baseComparator);
    }
  }
}
