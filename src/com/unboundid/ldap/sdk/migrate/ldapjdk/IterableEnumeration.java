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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an {@code Enumeration} that is based
 * on an {@code Iterable} object.
 *
 * @param  <T>  The type of object for this enumeration.
 */
@InternalUseOnly()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class IterableEnumeration<T>
      implements Enumeration<T>
{
  // The iteration over which this enumeration operates.
  @NotNull private final Iterator<T> iterator;



  /**
   * Creates a new enumeration for the provided {@code Iterable} object.
   *
   * @param  i  The {@code Iterable} object to use to create this enumeration.
   */
  IterableEnumeration(@NotNull final Iterable<T> i)
  {
    iterator = i.iterator();
  }



  /**
   * Indicates whether this enumeration has any more elements.
   *
   * @return  {@code true} if this enumeration has at least one more element, or
   *          {@code false} if not.
   */
  @Override()
  public boolean hasMoreElements()
  {
    return iterator.hasNext();
  }



  /**
   * Retrieves the next element from this enumeration.
   *
   * @return  The next element for this enumeration.
   *
   * @throws  NoSuchElementException  If there are no more elements to retrieve.
   */
  @Override()
  @NotNull()
  public T nextElement()
         throws NoSuchElementException
  {
    return iterator.next();
  }
}
