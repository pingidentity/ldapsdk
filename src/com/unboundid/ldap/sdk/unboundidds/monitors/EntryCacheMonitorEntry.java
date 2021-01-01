/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
 * This class defines a monitor entry that provides general information about
 * the state of the Directory Server entry cache.
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
 * The information that may be available in the entry cache monitor entry
 * includes:
 * <UL>
 *   <LI>The number of cache tries, which are attempts to retrieve entries from
 *       the cache.</LI>
 *   <LI>The number of cache hits, which are successful attempts to retrieve an
 *       entry from the cache.</LI>
 *   <LI>The number of cache misses, which are unsuccessful attempts to retrieve
 *       an entry from the cache.</LI>
 *   <LI>The cache hit ratio, which is the ratio of the time that a cache try is
 *       successful.</LI>
 *   <LI>The number of entries currently held in the cache.</LI>
 *   <LI>The maximum number of entries that may be held in the cache.</LI>
 *   <LI>The approximate current amount of memory consumed by the cache.</LI>
 *   <LI>The maximum amount of memory that may be consumed by the cache.</LI>
 * </UL>
 * The server should present at most one client connection monitor entry.  It
 * can be retrieved using the
 * {@link MonitorManager#getEntryCacheMonitorEntry} method.  This entry provides
 * specific methods for accessing information about the entry cache (e.g., the
 * {@link EntryCacheMonitorEntry#getCurrentCount} method can be used
 * to retrieve the number of entries currently in the cache).  Alternately, this
 * information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EntryCacheMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in entry cache monitor entries.
   */
  @NotNull static final String ENTRY_CACHE_MONITOR_OC =
       "ds-entry-cache-monitor-entry";



  /**
   * The name of the attribute that provides the number of entries currently
   * held in the cache.
   */
  @NotNull private static final String ATTR_CURRENT_COUNT =
       "currentEntryCacheCount";



  /**
   * The name of the attribute that provides the current entry cache size in
   * bytes.
   */
  @NotNull private static final String ATTR_CURRENT_SIZE =
       "currentEntryCacheSize";



  /**
   * The name of the attribute that provides the entry cache hit ratio.
   */
  @NotNull private static final String ATTR_HIT_RATIO = "entryCacheHitRatio";



  /**
   * The name of the attribute that provides the number of cache hits.
   */
  @NotNull private static final String ATTR_HITS = "entryCacheHits";



  /**
   * The name of the attribute that provides the maximum number of entries that
   * may be held in the cache.
   */
  @NotNull private static final String ATTR_MAX_COUNT = "maxEntryCacheCount";



  /**
   * The name of the attribute that provides the maximum entry cache size in
   * bytes.
   */
  @NotNull private static final String ATTR_MAX_SIZE = "maxEntryCacheSize";



  /**
   * The name of the attribute that provides the number of cache tries.
   */
  @NotNull private static final String ATTR_TRIES = "entryCacheTries";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2468261007112908567L;



  // The hit ratio.
  @Nullable private final Double hitRatio;

  // The number of cache hits.
  @Nullable private final Long cacheHits;

  // The number of cache misses.
  @Nullable private final Long cacheMisses;

  // The number of cache tries.
  @Nullable private final Long cacheTries;

  // The current number of entries in the cache.
  @Nullable private final Long currentCount;

  // The current size of the cache.
  @Nullable private final Long currentSize;

  // The maximum number of entries in the cache.
  @Nullable private final Long maxCount;

  // The maximum size of the cache.
  @Nullable private final Long maxSize;



  /**
   * Creates a new entry cache monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as an entry cache monitor entry.  It
   *                must not be {@code null}.
   */
  public EntryCacheMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    cacheHits    = getLong(ATTR_HITS);
    cacheTries   = getLong(ATTR_TRIES);
    hitRatio     = getDouble(ATTR_HIT_RATIO);
    currentCount = getLong(ATTR_CURRENT_COUNT);
    maxCount     = getLong(ATTR_MAX_COUNT);
    currentSize  = getLong(ATTR_CURRENT_SIZE);
    maxSize      = getLong(ATTR_MAX_SIZE);

    if ((cacheHits == null) || (cacheTries == null))
    {
      cacheMisses = null;
    }
    else
    {
      cacheMisses = cacheTries - cacheHits;
    }
  }



  /**
   * Retrieves the number of attempts to find an entry in the cache.
   *
   * @return  The number of attempts to find an entry in the cache, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCacheTries()
  {
    return cacheTries;
  }



  /**
   * Retrieves the number of attempts to find an entry in the cache in which the
   * entry was found.
   *
   * @return  The number of attempts to find an entry in the cache in which the
   *          entry was found, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getCacheHits()
  {
    return cacheHits;
  }



  /**
   * Retrieves the number of attempts to find an entry in the cache in which the
   * entry was not found.
   *
   * @return  The number of attempts to find an entry in the cache in which the
   *          entry was not found, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getCacheMisses()
  {
    return cacheMisses;
  }



  /**
   * Retrieves the ratio of the time a requested entry was found in the cache.
   *
   * @return  The ratio of the time a requested entry was found in the cache, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Double getCacheHitRatio()
  {
    return hitRatio;
  }



  /**
   * Retrieves the number of entries currently held in the entry cache.
   *
   * @return  The number of entries currently held in the entry cache, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentCount()
  {
    return currentCount;
  }



  /**
   * Retrieves the maximum number of entries that may be held in the entry
   * cache.
   *
   * @return  The maximum number of entries that may be held in the entry cache,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaxCount()
  {
    return maxCount;
  }



  /**
   * Retrieves the current amount of memory (in bytes) consumed by the entry
   * cache.
   *
   * @return  The current amount of memory (in bytes) consumed by the entry
   *          cache, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getCurrentCacheSize()
  {
    return currentSize;
  }



  /**
   * Retrieves the maximum amount of memory (in bytes) that may be consumed by
   * the entry cache.
   *
   * @return  The maximum amount of memory (in bytes) that may be consumed by
   *          the entry cache, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getMaxCacheSize()
  {
    return maxSize;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_ENTRY_CACHE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_ENTRY_CACHE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(20));

    if (cacheTries != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TRIES,
           INFO_ENTRY_CACHE_DISPNAME_TRIES.get(),
           INFO_ENTRY_CACHE_DESC_TRIES.get(),
           cacheTries);
    }

    if (cacheHits != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HITS,
           INFO_ENTRY_CACHE_DISPNAME_HITS.get(),
           INFO_ENTRY_CACHE_DESC_HITS.get(),
           cacheHits);
    }

    if (cacheMisses != null)
    {
      addMonitorAttribute(attrs,
           "entryCacheMisses",
           INFO_ENTRY_CACHE_DISPNAME_MISSES.get(),
           INFO_ENTRY_CACHE_DESC_MISSES.get(),
           cacheMisses);
    }

    if (hitRatio != null)
    {
      addMonitorAttribute(attrs,
           ATTR_HIT_RATIO,
           INFO_ENTRY_CACHE_DISPNAME_HIT_RATIO.get(),
           INFO_ENTRY_CACHE_DESC_HIT_RATIO.get(),
           hitRatio);
    }

    if (currentCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_COUNT,
           INFO_ENTRY_CACHE_DISPNAME_CURRENT_COUNT.get(),
           INFO_ENTRY_CACHE_DESC_CURRENT_COUNT.get(),
           currentCount);
    }

    if (maxCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_COUNT,
           INFO_ENTRY_CACHE_DISPNAME_MAX_COUNT.get(),
           INFO_ENTRY_CACHE_DESC_MAX_COUNT.get(),
           maxCount);
    }

    if (currentSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_SIZE,
           INFO_ENTRY_CACHE_DISPNAME_CURRENT_SIZE.get(),
           INFO_ENTRY_CACHE_DESC_CURRENT_SIZE.get(),
           currentSize);
    }

    if (maxSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_SIZE,
           INFO_ENTRY_CACHE_DISPNAME_MAX_SIZE.get(),
           INFO_ENTRY_CACHE_DESC_MAX_SIZE.get(),
           maxSize);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
