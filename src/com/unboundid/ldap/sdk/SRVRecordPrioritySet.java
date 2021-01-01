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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadLocalRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for holding information about a set of
 * DNS SRV records with the same priority.  Records are organized into those
 * with nonzero weights and those with zero weights.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecordPrioritySet
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7722028520625558942L;



  // The priority for all records in this set.
  private final long priority;

  // The total weight for all servers in this set.
  private final long totalWeight;

  // The set of all records in this set.
  @NotNull private final List<SRVRecord> allRecords;

  // The set of records with nonzero weights.
  @NotNull private final List<SRVRecord> nonzeroWeightRecords;

  // The set of records with zero weights.
  @NotNull private final List<SRVRecord> zeroWeightRecords;



  /**
   * Creates a new SRV record priority set with the provided records.
   *
   * @param  priority  The priority for all records in this set.
   * @param  records   The set of records with the same priority.  It must not
   *                   be {@code null} or empty.
   */
  SRVRecordPrioritySet(final long priority,
                       @NotNull final List<SRVRecord> records)
  {
    this.priority = priority;

    long w = 0L;

    final ArrayList<SRVRecord> nRecords = new ArrayList<>(records.size());
    final ArrayList<SRVRecord> zRecords = new ArrayList<>(records.size());

    for (final SRVRecord r : records)
    {
      if (r.getWeight() == 0L)
      {
        zRecords.add(r);
      }
      else
      {
        nRecords.add(r);
        w += r.getWeight();
      }
    }

    totalWeight = w;

    allRecords           = Collections.unmodifiableList(records);
    nonzeroWeightRecords = Collections.unmodifiableList(nRecords);
    zeroWeightRecords    = Collections.unmodifiableList(zRecords);
  }



  /**
   * Retrieves the priority for all records in this set.
   *
   * @return  The priority for all records in this set.
   */
  long getPriority()
  {
    return priority;
  }



  /**
   * Retrieves a list of SRV records in the order that they should be accessed.
   *
   * @return  A list of SRV records in the order that they should be accessed.
   */
  @NotNull()
  List<SRVRecord> getOrderedRecords()
  {
    final ArrayList<SRVRecord> records = new ArrayList<>(allRecords.size());

    if (! nonzeroWeightRecords.isEmpty())
    {
      if (nonzeroWeightRecords.size() == 1)
      {
        records.addAll(nonzeroWeightRecords);
      }
      else
      {
        final Random r = ThreadLocalRandom.get();
        long tw = totalWeight;
        final ArrayList<SRVRecord> rl = new ArrayList<>(nonzeroWeightRecords);
        while (! rl.isEmpty())
        {
          long w = ((r.nextLong() & 0x7FFF_FFFF_FFFF_FFFFL) % tw);
          final Iterator<SRVRecord> iterator = rl.iterator();
          while (iterator.hasNext())
          {
            final SRVRecord record = iterator.next();
            if ((w < record.getWeight()) || (! iterator.hasNext()))
            {
              iterator.remove();
              records.add(record);
              tw -= record.getWeight();
              break;
            }
            else
            {
              w -= record.getWeight();
            }
          }
        }
      }
    }

    records.addAll(zeroWeightRecords);
    return records;
  }



  /**
   * Retrieves a string representation of this priority server set.
   *
   * @return  A string representation of this priority server set.
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
   * Appends a string representation of this priority buffer set to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  private void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SRVRecordPrioritySet(records={");

    final Iterator<SRVRecord> iterator = allRecords.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().toString());
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
