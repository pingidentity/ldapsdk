/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.lang.ref.WeakReference;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;



/**
 * This class provides a weak hash set, which maintains weak references to the
 * elements it contains, so that they will be removed automatically once there
 * are no more normal references to them.
 * <BR><BR>
 * Note that because this set uses weak references, elements may disappear from
 * the set at any time without being explicitly removed.  This means that care
 * must be taken to ensure that the result of one method must not be considered
 * authoritative for subsequent calls to the same method or other methods in
 * this class.
 *
 * @param  <T>  The type of element held in this set.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class WeakHashSet<T>
       implements Set<T>
{
  // The map that will be used to provide the set implementation.
  @NotNull private final WeakHashMap<T,WeakReference<T>> m;



  /**
   * Creates a new weak hash set with the default initial capacity.
   */
  public WeakHashSet()
  {
    m = new WeakHashMap<>(16);
  }



  /**
   * Creates a new weak hash set with the specified initial capacity.
   *
   * @param  initialCapacity  The initial capacity for this weak hash set.  It
   *                          must not be {@code null}.
   */
  public WeakHashSet(final int initialCapacity)
  {
    m = new WeakHashMap<>(initialCapacity);
  }



  /**
   * Clears the contents of this set.
   */
  @Override()
  public void clear()
  {
    m.clear();
  }



  /**
   * Indicates whether this set is currently empty.
   *
   * @return  {@code true} if this set is empty, or {@code false} if not.
   */
  @Override()
  public boolean isEmpty()
  {
    return m.isEmpty();
  }



  /**
   * Retrieves the number of elements currently held in this set.
   *
   * @return  The number of elements currently held in this set.
   */
  @Override()
  public int size()
  {
    return m.size();
  }



  /**
   * Indicates whether this set contains the specified element.
   *
   * @param  e  The element for which to make the determination.
   *
   * @return  {@code true} if this set contains the specified element, or
   *          {@code false} if not.
   */
  @Override()
  public boolean contains(@NotNull final Object e)
  {
    return m.containsKey(e);
  }



  /**
   * Indicates whether this set currently contains all of the elements in the
   * provided collection.
   *
   * @param  c  The collection for which to make the determination.
   *
   * @return  {@code true} if this set currently contains all of the elements in
   *          the provided collection, or {@code false} if not.
   */
  @Override()
  public boolean containsAll(@NotNull final Collection<?> c)
  {
    return m.keySet().containsAll(c);
  }



  /**
   * Retrieves the existing instance of the provided element from this set.
   *
   * @param  e  The object for which to obtain the existing element.
   *
   * @return  The existing instance of the provided element, or {@code null} if
   *          the provided element is not contained in this set.
   */
  @Nullable()
  public T get(@NotNull final T e)
  {
    final WeakReference<T> r = m.get(e);
    if (r == null)
    {
      return null;
    }
    else
    {
      return r.get();
    }
  }



  /**
   * Adds the provided element to this set, if it does not already exist.
   *
   * @param  e  The element to be added to the set if it does not already exist.
   *
   * @return  {@code true} if the element was added to the set (because it was
   *          not already present), or {@code false} if the element was not
   *          added (because it was already in the set).
   */
  @Override()
  public boolean add(@NotNull final T e)
  {
    if (m.containsKey(e))
    {
      return false;
    }
    else
    {
      m.put(e, new WeakReference<>(e));
      return true;
    }
  }



  /**
   * Adds any elements from the provided collection to this set if they were
   * not already present.
   *
   * @param  c  The collection containing elements to add.
   *
   * @return  {@code true} if at least one of the elements was not already in
   *          the set and was added, or {@code false} if no elements were added
   *          because they were already all present.
   */
  @Override()
  public boolean addAll(@NotNull final Collection<? extends T> c)
  {
    boolean changed = false;
    for (final T e : c)
    {
      if (! m.containsKey(e))
      {
        m.put(e, new WeakReference<>(e));
        changed = true;
      }
    }

    return changed;
  }



  /**
   * Adds the provided element to the set if it does not already exist, and
   * retrieves the value stored in the set.
   *
   * @param  e  The element to be added to the set if it does not already exist.
   *
   * @return  An existing version of the provided element if it was already in
   *          the set, or the provided object if it was just added.
   */
  @Nullable()
  public T addAndGet(@NotNull final T e)
  {
    final WeakReference<T> r = m.get(e);
    if (r != null)
    {
      final T existingElement = r.get();
      if (existingElement != null)
      {
        return existingElement;
      }
    }

    m.put(e, new WeakReference<>(e));
    return e;
  }



  /**
   * Removes the specified element from this set, if it exists.
   *
   * @param  e  The element to be removed from this set.
   *
   * @return  {@code true} if the element existed in the set and was removed, or
   *          {@code false} if not.
   */
  @Override()
  public boolean remove(@NotNull final Object e)
  {
    return (m.remove(e) != null);
  }



  /**
   * Removes all of the elements of the provided collection from this set.
   *
   * @param  c  The collection containing the elements to remove from this set.
   *
   * @return  {@code true} if at least one of the elements from the provided
   *          collection were contained in and therefore removed from the set,
   *          or {@code false} if none of the elements in the given collection
   *          were contained in this set.
   */
  @Override()
  public boolean removeAll(@NotNull final Collection<?> c)
  {
    boolean changed = false;
    for (final Object o : c)
    {
      final Object e = m.remove(o);
      if (e != null)
      {
        changed = true;
      }
    }

    return changed;
  }



  /**
   * Removes all elements from this set which are not contained in the provided
   * collection.
   *
   * @param  c  The collection of elements to be retained.
   *
   * @return  {@code true} if this set contained at least one element not in the
   *          provided collection that was therefore removed, or {@code false}
   *          if this set did not have any elements that were not in the
   *          provided collection.
   */
  @Override()
  public boolean retainAll(@NotNull final Collection<?> c)
  {
    boolean changed = false;
    final Iterator<Map.Entry<T,WeakReference<T>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<T,WeakReference<T>> e = iterator.next();
      if (! c.contains(e.getKey()))
      {
        iterator.remove();
        changed = true;
      }
    }

    return changed;
  }



  /**
   * Retrieves an iterator across all elements in this set.
   *
   * @return  An iterator across all elements in this set.
   */
  @Override()
  @NotNull()
  public Iterator<T> iterator()
  {
    return m.keySet().iterator();
  }



  /**
   * Retrieves an array containing all of the elements currently held in this
   * set.
   *
   * @return  An array containing all of the elements currently held in this
   *          set.
   */
  @Override()
  @NotNull()
  public Object[] toArray()
  {
    return m.keySet().toArray();
  }



  /**
   * Retrieves an array containing all of the elements currently held in this
   * set.
   *
   * @param  a  An array into which the elements will be added if there is
   *            sufficient space.
   *
   * @param  <E>  The type of element for the given array.
   *
   * @return  The provided array (with the first {@code null} element depicting
   *          the end of the set elements if the given array is larger than this
   *          set), or a newly-allocated array if the provided array was not
   *          large enough.
   */
  @Override()
  @NotNull()
  public <E> E[] toArray(@NotNull final E[] a)
  {
    return m.keySet().toArray(a);
  }



  /**
   * Retrieves a hash code for this set.
   *
   * @return  A hash code for this set.
   */
  @Override()
  public int hashCode()
  {
    return m.keySet().hashCode();
  }



  /**
   * Indicates whether the provided object is equal to this set.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a non-{@code null} set with
   *          the same elements as this set, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    return ((o != null) && (o instanceof Set) && m.keySet().equals(o));
  }



  /**
   * Retrieves a string representation of this set.
   *
   * @return  A string representation of this set.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return m.keySet().toString();
  }
}
