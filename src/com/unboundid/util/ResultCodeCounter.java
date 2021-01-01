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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a utility that may be used to count operation results and
 * categorize them based on the total number of results of each type.  It also
 * provides a method for retrieving result code counts, sorted by the number of
 * occurrences for each.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ResultCodeCounter
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2280620218815022241L;



  // The reference to the current map used to hold result code counts.
  @NotNull private final
       AtomicReference<ConcurrentHashMap<ResultCode,AtomicLong>> rcMap;



  /**
   * Creates a new instance of this result code counter.
   */
  public ResultCodeCounter()
  {
    rcMap = new AtomicReference<>();
    rcMap.set(new ConcurrentHashMap<ResultCode,AtomicLong>(
         StaticUtils.computeMapCapacity(ResultCode.values().length)));
  }



  /**
   * Increments the count for the provided result code.
   *
   * @param  resultCode  The result code for which to increment the count.
   */
  public void increment(@NotNull final ResultCode resultCode)
  {
    increment(resultCode, 1);
  }



  /**
   * Increments the count for the provided result code by the specified amount.
   *
   * @param  resultCode  The result code for which to increment the count.
   * @param  amount      The amount by which to increment the count.
   */
  public void increment(@NotNull final ResultCode resultCode, final int amount)
  {
    final ConcurrentHashMap<ResultCode,AtomicLong> m = rcMap.get();

    AtomicLong l = m.get(resultCode);
    if (l == null)
    {
      l = new AtomicLong(0L);
      final AtomicLong l2 = m.putIfAbsent(resultCode, l);
      if (l2 != null)
      {
        l = l2;
      }
    }

    l.addAndGet(amount);
  }



  /**
   * Clears all collected data from the result code counter.  Any
   * previously-collected data will be lost.
   */
  public void reset()
  {
    rcMap.set(new ConcurrentHashMap<ResultCode,AtomicLong>(
         StaticUtils.computeMapCapacity(ResultCode.values().length)));
  }



  /**
   * Retrieves a list of the result codes of each type along with their
   * respective counts.  The returned list will be sorted by number of
   * occurrences, from most frequent to least frequent.
   *
   * @param  reset  Indicates whether to clear the results after obtaining
   *                them.
   *
   * @return  A list of the result codes of each type along with their
   *          respective counts.
   */
  @NotNull()
  public List<ObjectPair<ResultCode,Long>> getCounts(final boolean reset)
  {
    final ConcurrentHashMap<ResultCode,AtomicLong> m;
    if (reset)
    {
      m = rcMap.getAndSet(new ConcurrentHashMap<ResultCode,AtomicLong>(
           StaticUtils.computeMapCapacity(ResultCode.values().length)));
    }
    else
    {
      m = new ConcurrentHashMap<>(rcMap.get());
    }


    if (m.isEmpty())
    {
      return Collections.emptyList();
    }


    final TreeMap<Long,TreeMap<Integer,ResultCode>> sortedMap =
         new TreeMap<>(new ReverseComparator<Long>());
    for (final Map.Entry<ResultCode,AtomicLong> e : m.entrySet())
    {
      final long l = e.getValue().longValue();
      TreeMap<Integer,ResultCode> rcByValue = sortedMap.get(l);
      if (rcByValue == null)
      {
        rcByValue = new TreeMap<>();
        sortedMap.put(l, rcByValue);
      }

      final ResultCode rc = e.getKey();
      rcByValue.put(rc.intValue(), rc);
    }


    final ArrayList<ObjectPair<ResultCode,Long>> rcCounts =
         new ArrayList<>(2*sortedMap.size());
    for (final Map.Entry<Long,TreeMap<Integer,ResultCode>> e :
         sortedMap.entrySet())
    {
      final long count = e.getKey();
      for (final ResultCode rc : e.getValue().values())
      {
        rcCounts.add(new ObjectPair<>(rc, count));
      }
    }

    return Collections.unmodifiableList(rcCounts);
  }
}
