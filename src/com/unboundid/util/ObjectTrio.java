/*
 * Copyright 2023-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2024 Ping Identity Corporation
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
 * Copyright (C) 2023-2024 Ping Identity Corporation
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



/**
 * This class provides a typed trio of objects.  It may be used whenever three
 * objects are required but only one is allowed (e.g., returning three values
 * from a method).
 *
 * @param  <F>  The type of the first object.
 * @param  <S>  The type of the second object.
 * @param  <T>  The type of the third object.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectTrio<F,S,T>
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1205337843902801247L;



  // The first object in this trio.
  @Nullable private final F first;

  // The second object in this trio.
  @Nullable private final S second;

  // The third object in this trio.
  @Nullable private final T third;



  /**
   * Creates a new object trio with the provided elements.
   *
   * @param  first   The first object in this trio.
   * @param  second  The second object in this trio.
   * @param  third   The third object in this trio.
   */
  public ObjectTrio(@Nullable final F first,
                    @Nullable final S second,
                    @Nullable final T third)
  {
    this.first = first;
    this.second = second;
    this.third = third;
  }



  /**
   * Retrieves the first object in  this trio.
   *
   * @return  The first object in this trio.
   */
  @Nullable()
  public F getFirst()
  {
    return first;
  }



  /**
   * Retrieves the second object in this trio.
   *
   * @return  The second object in this trio.
   */
  @Nullable()
  public S getSecond()
  {
    return second;
  }



  /**
   * Retrieves the third object in this trio.
   *
   * @return  The third object in this trio.
   */
  @Nullable()
  public T getThird()
  {
    return third;
  }



  /**
   * Retrieves a hash code for this object trio.
   *
   * @return  A hash code for this object trio.
   */
  @Override()
  public int hashCode()
  {
    int h = 0;

    if (first != null)
    {
      h += first.hashCode();
    }

    if (second != null)
    {
      h += second.hashCode();
    }

    if (third != null)
    {
      h += third.hashCode();
    }

    return h;
  }



  /**
   * Indicates whether the provided object is equal to this object trio.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this object trio,
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

    if (o instanceof ObjectTrio)
    {
      final ObjectTrio<?,?,?> t = (ObjectTrio<?,?,?>) o;
      if (first == null)
      {
        if (t.first != null)
        {
          return false;
        }
      }
      else
      {
        if (! first.equals(t.first))
        {
          return false;
        }
      }

      if (second == null)
      {
        if (t.second != null)
        {
          return false;
        }
      }
      else
      {
        if (! second.equals(t.second))
        {
          return false;
        }
      }

      if (third == null)
      {
        if (t.third != null)
        {
          return false;
        }
      }
      else
      {
        if (! third.equals(t.third))
        {
          return false;
        }
      }

      return true;
    }

    return false;
  }



  /**
   * Retrieves a string representation of this object trio.
   *
   * @return  A string representation of this object trio.
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
   * Appends a string representation of this object trio to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ObjectTrio(first=");
    buffer.append(String.valueOf(first));
    buffer.append(", second=");
    buffer.append(String.valueOf(second));
    buffer.append(", third=");
    buffer.append(String.valueOf(third));
    buffer.append(')');
  }
}
