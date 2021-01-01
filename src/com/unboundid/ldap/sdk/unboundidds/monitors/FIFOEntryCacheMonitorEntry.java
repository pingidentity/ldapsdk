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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the sate
 * of a FIFO entry cache in the Directory Server.
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
 * The information that may be available about the entry cache includes:
 * <UL>
 *   <LI>The name assigned to the cache.</LI>
 *   <LI>The number of attempts (successful and total) and the hit ratio when
 *       trying to retrieve an entry from the cache.</LI>
 *   <LI>The maximum allowed size of the entry cache in entries and bytes.</LI>
 *   <LI>The number of entries currently held in the cache.</LI>
 *   <LI>The number of entries added to or updated in the cache.</LI>
 *   <LI>The number of times an entry was not added to the cache because it was
 *       already present.</LI>
 *   <LI>The number of times an entry was not added to the cache because it did
 *       not match filter criteria required for inclusion.</LI>
 *   <LI>The number of times an entry was not added to the cache because it was
 *       too small to be included.</LI>
 *   <LI>The number of times an entry was evicted because of memory pressure or
 *       to make room for new entries.</LI>
 *   <LI>Information about the current memory consumption of the cache and
 *       whether the cache is currently full.</LI>
 * </UL>
 * The server will automatically present one monitor entry for every FIFO entry
 * cache defined in the server.  It is possible to have multiple caches enabled
 * if desired (e.g., one specifically targeting large static groups, and another
 * small cache to help improve write-after-read performance).  FIFO entry cache
 * monitor entries can be retrieved using the
 * {@link MonitorManager#getFIFOEntryCacheMonitorEntries} method.  These monitor
 * entries provide specific methods for accessing information about the FIFO
 * entry cache.  Alternately, this information may be accessed using the generic
 * API.  See the {@link MonitorManager} class documentation for an example that
 * demonstrates the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FIFOEntryCacheMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in entry cache monitor entries.
   */
  @NotNull static final String FIFO_ENTRY_CACHE_MONITOR_OC =
       "ds-fifo-entry-cache-monitor-entry";



  /**
   * The name of the attribute that holds the name of the associated FIFO entry
   * cache.
   */
  @NotNull private static final String ATTR_CACHE_NAME = "cacheName";



  /**
   * The name of the attribute that holds the number of cache hits.
   */
  @NotNull private static final String ATTR_ENTRY_CACHE_HITS = "entryCacheHits";



  /**
   * The name of the attribute that holds the number of cache tries.
   */
  @NotNull private static final String ATTR_ENTRY_CACHE_TRIES =
       "entryCacheTries";



  /**
   * The name of the attribute that holds the cache hit ratio.
   */
  @NotNull private static final String ATTR_ENTRY_CACHE_HIT_RATIO =
       "entryCacheHitRatio";



  /**
   * The name of the attribute that holds the maximum cache size in bytes.
   */
  @NotNull private static final String ATTR_MAX_ENTRY_CACHE_SIZE =
       "maxEntryCacheSize";



  /**
   * The name of the attribute that holds the number of entries currently in the
   * cache.
   */
  @NotNull private static final String ATTR_CURRENT_ENTRY_CACHE_COUNT =
       "currentEntryCacheCount";



  /**
   * The name of the attribute that holds the maximum number of entries that may
   * be held in the cache.
   */
  @NotNull private static final String ATTR_MAX_ENTRY_CACHE_COUNT =
       "maxEntryCacheCount";



  /**
   * The name of the attribute that holds the number of entries added to or
   * replaced in the cache.
   */
  @NotNull private static final String ATTR_ENTRIES_ADDED_OR_UPDATED =
       "entriesAddedOrUpdated";



  /**
   * The name of the attribute that holds the number of entries evicted because
   * the entry cache had reached its maximum memory allocation.
   */
  @NotNull private static final String ATTR_EVICTIONS_DUE_TO_MAX_MEMORY =
       "evictionsDueToMaxMemory";



  /**
   * The name of the attribute that holds the number of entries evicted because
   * the entry cache had reached its maximum entry count.
   */
  @NotNull private static final String ATTR_EVICTIONS_DUE_TO_MAX_ENTRIES =
       "evictionsDueToMaxEntries";



  /**
   * The name of the attribute that holds the number of entries that were not
   * added because they were already present in the cache.
   */
  @NotNull private static final String ATTR_ENTRIES_NOT_ADDED_ALREADY_PRESENT =
       "entriesNotAddedAlreadyPresent";



  /**
   * The name of the attribute that holds the number of entries that were not
   * added because the cache had reached its maximum memory allocation.
   */
  @NotNull private static final String
       ATTR_ENTRIES_NOT_ADDED_DUE_TO_MAX_MEMORY =
            "entriesNotAddedDueToMaxMemory";



  /**
   * The name of the attribute that holds the number of entries that were not
   * added because they did not meet the necessary filter criteria.
   */
  @NotNull private static final String ATTR_ENTRIES_NOT_ADDED_DUE_TO_FILTER =
       "entriesNotAddedDueToFilter";



  /**
   * The name of the attribute that holds the number of entries that were not
   * added because they did not have enough values to be considered for
   * inclusion in the cache.
   */
  @NotNull private static final String
       ATTR_ENTRIES_NOT_ADDED_DUE_TO_ENTRY_SMALLNESS =
            "entriesNotAddedDueToEntrySmallness";



  /**
   * The name of the attribute that holds the number of times that entries were
   * purged from the cache because the JVM was running low on memory.
   */
  @NotNull private static final String ATTR_LOW_MEMORY_OCCURRENCES =
       "lowMemoryOccurrences";



  /**
   * The name of the attribute that holds the percentage of the maximum allowed
   * number of entries that are currently held in the cache.
   */
  @NotNull private static final String ATTR_PERCENT_FULL_MAX_ENTRIES =
       "percentFullMaxEntries";



  /**
   * The name of the attribute that holds the maximum percent of JVM memory that
   * may be consumed before entries may stop being added to the cache.
   */
  @NotNull private static final String ATTR_JVM_MEMORY_MAX_PERCENT_THRESHOLD =
       "jvmMemoryMaxPercentThreshold";



  /**
   * The name of the attribute that holds the percent of JVM memory that is
   * currently consumed.
   */
  @NotNull private static final String ATTR_JVM_MEMORY_CURRENT_PERCENT_FULL =
       "jvmMemoryCurrentPercentFull";



  /**
   * The name of the attribute that holds the difference between the maximum
   * memory percent threshold and the current percent full.
   */
  @NotNull private static final String
       ATTR_JVM_MEMORY_BELOW_MAX_MEMORY_PERCENT =
            "jvmMemoryBelowMaxMemoryPercent";



  /**
   * The name of the attribute that indicates whether the entry cache is
   * currently full (based on memory usage or number of entries).
   */
  @NotNull private static final String ATTR_IS_FULL = "isFull";



  /**
   * The name of the attribute that holds a human-readable message about the
   * capacity and utilization of the cache.
   */
  @NotNull private static final String ATTR_CAPACITY_DETAILS =
       "capacityDetails";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3340643698412829407L;



  // The value of the isFull attribute.
  @Nullable private final Boolean isFull;

  // The value of the currentEntryCacheCount attribute.
  @Nullable private final Long currentEntryCacheCount;

  // The value of the entriesAddedOrUpdated attribute.
  @Nullable private final Long entriesAddedOrUpdated;

  // The value of the entriesNotAddedAlreadyPresent attribute.
  @Nullable private final Long entriesNotAddedAlreadyPresent;

  // The value of the entriesNotAddedDueToEntrySmallness attribute.
  @Nullable private final Long entriesNotAddedDueToEntrySmallness;

  // The value of the entriesNotAddedDueToFilter attribute.
  @Nullable private final Long entriesNotAddedDueToFilter;

  // The value of the entriesNotAddedDueToMaxMemory attribute.
  @Nullable private final Long entriesNotAddedDueToMaxMemory;

  // The value of the entryCacheHitRatio attribute.
  @Nullable private final Long entryCacheHitRatio;

  // The value of the entryCacheHits attribute.
  @Nullable private final Long entryCacheHits;

  // The value of the entryCacheTries attribute.
  @Nullable private final Long entryCacheTries;

  // The value of the evictionsDueToMaxEntries attribute.
  @Nullable private final Long evictionsDueToMaxEntries;

  // The value of the evictionsDueToMaxMemory attribute.
  @Nullable private final Long evictionsDueToMaxMemory;

  // The value of the jvmMemoryBelowMaxMemoryPercent attribute.
  @Nullable private final Long jvmMemoryBelowMaxMemoryPercent;

  // The value of the jvmMemoryCurrentPercentFull attribute.
  @Nullable private final Long jvmMemoryCurrentPercentFull;

  // The value of the jvmMemoryMaxPercentThreshold attribute.
  @Nullable private final Long jvmMemoryMaxPercentThreshold;

  // The value of the lowMemoryOccurrences attribute.
  @Nullable private final Long lowMemoryOccurrences;

  // The value of the maxEntryCacheCount attribute.
  @Nullable private final Long maxEntryCacheCount;

  // The value of the maxEntryCacheSize attribute.
  @Nullable private final Long maxEntryCacheSize;

  // The value of the percentFullMaxEntries attribute.
  @Nullable private final Long percentFullMaxEntries;

  // The value of the cacheName attribute.
  @Nullable private final String cacheName;

  // The value of the capacityDetails attribute.
  @Nullable private final String capacityDetails;



  /**
   * Creates a new FIFO entry cache monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a FIFO entry cache monitor entry.
   *                It must not be {@code null}.
   */
  public FIFOEntryCacheMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    isFull = getBoolean(ATTR_IS_FULL);
    currentEntryCacheCount = getLong(ATTR_CURRENT_ENTRY_CACHE_COUNT);
    entriesAddedOrUpdated = getLong(ATTR_ENTRIES_ADDED_OR_UPDATED);
    entriesNotAddedAlreadyPresent =
         getLong(ATTR_ENTRIES_NOT_ADDED_ALREADY_PRESENT);
    entriesNotAddedDueToEntrySmallness =
         getLong(ATTR_ENTRIES_NOT_ADDED_DUE_TO_ENTRY_SMALLNESS);
    entriesNotAddedDueToFilter = getLong(ATTR_ENTRIES_NOT_ADDED_DUE_TO_FILTER);
    entriesNotAddedDueToMaxMemory =
         getLong(ATTR_ENTRIES_NOT_ADDED_DUE_TO_MAX_MEMORY);
    entryCacheHitRatio = getLong(ATTR_ENTRY_CACHE_HIT_RATIO);
    entryCacheHits = getLong(ATTR_ENTRY_CACHE_HITS);
    entryCacheTries = getLong(ATTR_ENTRY_CACHE_TRIES);
    evictionsDueToMaxEntries = getLong(ATTR_EVICTIONS_DUE_TO_MAX_ENTRIES);
    evictionsDueToMaxMemory = getLong(ATTR_EVICTIONS_DUE_TO_MAX_MEMORY);
    jvmMemoryBelowMaxMemoryPercent =
         getLong(ATTR_JVM_MEMORY_BELOW_MAX_MEMORY_PERCENT);
    jvmMemoryCurrentPercentFull = getLong(ATTR_JVM_MEMORY_CURRENT_PERCENT_FULL);
    jvmMemoryMaxPercentThreshold =
         getLong(ATTR_JVM_MEMORY_MAX_PERCENT_THRESHOLD);
    lowMemoryOccurrences = getLong(ATTR_LOW_MEMORY_OCCURRENCES);
    maxEntryCacheCount = getLong(ATTR_MAX_ENTRY_CACHE_COUNT);
    maxEntryCacheSize = getLong(ATTR_MAX_ENTRY_CACHE_SIZE);
    percentFullMaxEntries = getLong(ATTR_PERCENT_FULL_MAX_ENTRIES);
    cacheName = getString(ATTR_CACHE_NAME);
    capacityDetails = getString(ATTR_CAPACITY_DETAILS);
  }



  /**
   * Retrieves the name of the associated FIFO entry cache.
   *
   * @return  The name of the associated FIFO entry cache, or {@code null} if
   *          this was not included in the monitor entry.
   */
  @Nullable()
  public String getCacheName()
  {
    return cacheName;
  }



  /**
   * Retrieves the number of times that a requested entry was successfully found
   * in the cache.
   *
   * @return  The number of times that a requested entry was successfully found
   *          in the cache, or {@code null} if this was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getEntryCacheHits()
  {
    return entryCacheHits;
  }



  /**
   * Retrieves the number of times that an attempt was made to retrieve an entry
   * from the cache.
   *
   * @return  The number of times that an attempt was made to retrieve an entry
   *          from the cache, or {@code null} if this was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getEntryCacheTries()
  {
    return entryCacheTries;
  }



  /**
   * Retrieves the percentage of the time that a requested entry was
   * successfully retrieved from the cache.
   *
   * @return  The percentage of the time that a requested entry was successfully
   *          retrieved from the cache, or {@code null} if this was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getEntryCacheHitRatio()
  {
    return entryCacheHitRatio;
  }



  /**
   * Retrieves the maximum amount of memory (in bytes) that the entry cache may
   * consume.
   *
   * @return  The maximum amount of memory (in bytes) that the entry cache may
   *          consume, or {@code null} if this was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getMaxEntryCacheSizeBytes()
  {
    return maxEntryCacheSize;
  }



  /**
   * Retrieves the number of entries currently held in the entry cache.
   *
   * @return  The number of entries currently held in the entry cache, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentEntryCacheCount()
  {
    return currentEntryCacheCount;
  }



  /**
   * Retrieves the maximum number of entries that may be held in the entry
   * cache.
   *
   * @return  The maximum number of entries that may be held in the entry cache,
   *          or {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaxEntryCacheCount()
  {
    return maxEntryCacheCount;
  }



  /**
   * Retrieves the total number of entries that have been added to or updated
   * in the cache since it was enabled.
   *
   * @return  The total number of entries that have been added to or updated in
   *          the cache since it was enabled, or {@code null} if this was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getEntriesAddedOrUpdated()
  {
    return entriesAddedOrUpdated;
  }



  /**
   * Retrieves the number of times that an entry has been evicted from the cache
   * because the maximum memory consumption had been reached.
   *
   * @return  The number of times that an entry has been evicted from the cache
   *          because the maximum memory consumption had been reached, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getEvictionsDueToMaxMemory()
  {
    return evictionsDueToMaxMemory;
  }



  /**
   * Retrieves the maximum number of times that an entry has been evicted from
   * the cache because it already contained the maximum number of entries.
   *
   * @return  The maximum number of times that an entry has been evicted from
   *          the cache because it already contained the maximum number of
   *          entries, or {@code null} if this was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getEvictionsDueToMaxEntries()
  {
    return evictionsDueToMaxEntries;
  }



  /**
   * Retrieves the number of times that an entry was not added to the cache
   * because it was already present.
   *
   * @return  The number of times that an entry was not added to the cache
   *          because it was already present, or {@code null} if this was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getEntriesNotAddedAlreadyPresent()
  {
    return entriesNotAddedAlreadyPresent;
  }



  /**
   * Retrieves the number of times that an entry was not added to the cache
   * because it was already at its maximum memory consumption.
   *
   * @return  The number of times that an entry was not added to the cache
   *          because it was already at its maximum memory consumption, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getEntriesNotAddedDueToMaxMemory()
  {
    return entriesNotAddedDueToMaxMemory;
  }



  /**
   * Retrieves the number of times that an entry was not added to the cache
   * because it did not match the filter criteria for including it.
   *
   * @return  The number of times that an entry was not added to the cache
   *          because it did not match the filter criteria for including it, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getEntriesNotAddedDueToFilter()
  {
    return entriesNotAddedDueToFilter;
  }



  /**
   * Retrieves the number of times that an entry was not added to the cache
   * because it did not have enough values to be considered for inclusion.
   *
   * @return  The number of times that an entry was not added to the cache
   *          because it did not have enough values to be considered for
   *          inclusion, or {@code null} if this was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getEntriesNotAddedDueToEntrySmallness()
  {
    return entriesNotAddedDueToEntrySmallness;
  }



  /**
   * Retrieves the number of times that entries had to be evicted from the
   * cache because the available JVM memory became critically low.
   *
   * @return  The number of times that entries had to be evicted from the cache
   *          because the available JVM memory had become critically low, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getLowMemoryOccurrences()
  {
    return lowMemoryOccurrences;
  }



  /**
   * Retrieves the percentage of the maximum allowed number of entries that are
   * currently held in the cache.
   *
   * @return  The percentage of the maximum allowed number of entries that are
   *          currently held in the cache, or {@code null} if this was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getPercentFullMaxEntries()
  {
    return percentFullMaxEntries;
  }



  /**
   * Retrieves the maximum percent of JVM memory that may be consumed in order
   * for new entries to be added to the cache.
   *
   * @return  The maximum percent of JVM memory that may be consumed in order
   *          for new entries to be added to the cache, or {@code null} if this
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getJVMMemoryMaxPercentThreshold()
  {
    return jvmMemoryMaxPercentThreshold;
  }



  /**
   * Retrieves the percentage of JVM memory that is currently being consumed.
   *
   * @return  The percentage of JVM memory that is currently being consumed, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Long getJVMMemoryCurrentPercentFull()
  {
    return jvmMemoryCurrentPercentFull;
  }



  /**
   * Retrieves the difference between the JVM max memory percent threshold and
   * the JVM memory current percent full.  Note that this value may be negative
   * if the JVM is currently consuming more memory than the maximum threshold.
   *
   * @return  The difference between the JVM max memory percent threshold and
   *          the JVM memory current percent full, or {@code null} if this was
   *          not included in the monitor entry.
   */
  @Nullable()
  public Long getJVMMemoryBelowMaxMemoryPercent()
  {
    return jvmMemoryBelowMaxMemoryPercent;
  }



  /**
   * Indicates whether the entry cache is currently full, whether due to the
   * maximum JVM memory consumption or the maximum number of entries allowed in
   * the cache.
   *
   * @return  {@code Boolean.TRUE} if the entry cache is currently full,
   *          {@code Boolean.FALSE} if the entry cache is not yet full, or
   *          {@code null} if this was not included in the monitor entry.
   */
  @Nullable()
  public Boolean isFull()
  {
    return isFull;
  }



  /**
   * Retrieves a human-readable message about the capacity and utilization of
   * the entry cache.
   *
   * @return  A human-readable message about the capacity and utilization of the
   *          entry cache, or {@code null} if this was not included in the
   *          monitor entry.
   */
  @Nullable()
  public String getCapacityDetails()
  {
    return capacityDetails;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_FIFO_ENTRY_CACHE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_FIFO_ENTRY_CACHE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(30));

    if (cacheName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CACHE_NAME,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_CACHE_NAME.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_CACHE_NAME.get(),
           cacheName);
    }

    if (entryCacheHits != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRY_CACHE_HITS,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_HITS.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_HITS.get(),
           entryCacheHits);
    }

    if (entryCacheTries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRY_CACHE_TRIES,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_TRIES.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_TRIES.get(),
           entryCacheTries);
    }

    if (entryCacheHitRatio != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRY_CACHE_HIT_RATIO,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_HIT_RATIO.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_HIT_RATIO.get(),
           entryCacheHitRatio);
    }

    if (maxEntryCacheSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_ENTRY_CACHE_SIZE,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_MAX_MEM.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_MAX_MEM.get(),
           maxEntryCacheSize);
    }

    if (currentEntryCacheCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_ENTRY_CACHE_COUNT,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_CURRENT_COUNT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_CURRENT_COUNT.get(),
           currentEntryCacheCount);
    }

    if (maxEntryCacheCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_ENTRY_CACHE_COUNT,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_MAX_COUNT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_MAX_COUNT.get(),
           maxEntryCacheCount);
    }

    if (entriesAddedOrUpdated != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRIES_ADDED_OR_UPDATED,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_PUT_COUNT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_PUT_COUNT.get(),
           entriesAddedOrUpdated);
    }

    if (evictionsDueToMaxMemory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EVICTIONS_DUE_TO_MAX_MEMORY,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_EVICT_MEM.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_EVICT_MEM.get(),
           evictionsDueToMaxMemory);
    }

    if (evictionsDueToMaxEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EVICTIONS_DUE_TO_MAX_ENTRIES,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_EVICT_COUNT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_EVICT_COUNT.get(),
           evictionsDueToMaxEntries);
    }

    if (entriesNotAddedAlreadyPresent != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRIES_NOT_ADDED_ALREADY_PRESENT,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_NO_PUT_ALREADY_PRESENT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_NO_PUT_ALREADY_PRESENT.get(),
           entriesNotAddedAlreadyPresent);
    }

    if (entriesNotAddedDueToMaxMemory != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRIES_NOT_ADDED_DUE_TO_MAX_MEMORY,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_NO_PUT_MEM.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_NO_PUT_MEM.get(),
           entriesNotAddedDueToMaxMemory);
    }

    if (entriesNotAddedDueToFilter != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRIES_NOT_ADDED_DUE_TO_FILTER,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_NO_PUT_FILTER.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_NO_PUT_FILTER.get(),
           entriesNotAddedDueToFilter);
    }

    if (entriesNotAddedDueToEntrySmallness != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRIES_NOT_ADDED_DUE_TO_ENTRY_SMALLNESS,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_NO_PUT_TOO_SMALL.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_NO_PUT_TOO_SMALL.get(),
           entriesNotAddedDueToEntrySmallness);
    }

    if (lowMemoryOccurrences != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LOW_MEMORY_OCCURRENCES,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_LOW_MEM_COUNT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_LOW_MEM_COUNT.get(),
           lowMemoryOccurrences);
    }

    if (percentFullMaxEntries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PERCENT_FULL_MAX_ENTRIES,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_ENTRY_COUNT_PERCENT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_ENTRY_COUNT_PERCENT.get(),
           percentFullMaxEntries);
    }

    if (jvmMemoryMaxPercentThreshold != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_MEMORY_MAX_PERCENT_THRESHOLD,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_JVM_MEM_MAX_PERCENT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_JVM_MEM_MAX_PERCENT.get(),
           jvmMemoryMaxPercentThreshold);
    }

    if (jvmMemoryCurrentPercentFull != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_MEMORY_CURRENT_PERCENT_FULL,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_JVM_MEM_CURRENT_PERCENT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_JVM_MEM_CURRENT_PERCENT.get(),
           jvmMemoryCurrentPercentFull);
    }

    if (jvmMemoryBelowMaxMemoryPercent != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_MEMORY_BELOW_MAX_MEMORY_PERCENT,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_JVM_MEM_BELOW_MAX_PERCENT.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_JVM_MEM_BELOW_MAX_PERCENT.get(),
           jvmMemoryBelowMaxMemoryPercent);
    }

    if (isFull != null)
    {
      addMonitorAttribute(attrs,
           ATTR_IS_FULL,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_IS_FULL.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_IS_FULL.get(),
           isFull);
    }

    if (capacityDetails != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CAPACITY_DETAILS,
           INFO_FIFO_ENTRY_CACHE_DISPNAME_CAPACITY_DETAILS.get(),
           INFO_FIFO_ENTRY_CACHE_DESC_CAPACITY_DETAILS.get(),
           capacityDetails);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
