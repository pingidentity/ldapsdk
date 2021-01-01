/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
 * the state of an index in a Directory Server backend.  Note that the term
 * "index" may refer to a number of different things, including attribute
 * indexes (in which each individual index type will be considered a separate
 * index, so if "cn" has equality and substring index types then that will be
 * considered two separate indexes), VLV indexes, and system indexes (for
 * databases that are maintained internally, like id2entry, dn2id, id2children,
 * and id2subtree).
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
 * The set of index monitor entries published by the directory server can be
 * obtained using the {@link MonitorManager#getIndexMonitorEntries} method.
 * Specific methods are available for accessing the associated monitor data
 * (e.g., {@link IndexMonitorEntry#getBackendID} to retrieve the backend ID),
 * and there are also methods for accessing this information in a generic manner
 * (e.g., {@link IndexMonitorEntry#getMonitorAttributes} to retrieve all of
 * the monitor attributes).  See the {@link MonitorManager} class documentation
 * for an example that demonstrates the use of the generic API for accessing
 * monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IndexMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in index monitor entries.
   */
  @NotNull static final String INDEX_MONITOR_OC = "ds-index-monitor-entry";



  /**
   * The name of the attribute that contains the index name.
   */
  @NotNull private static final String ATTR_INDEX_NAME = "ds-index-name";



  /**
   * The name of the attribute that contains the backend ID.
   */
  @NotNull private static final String ATTR_BACKEND_ID = "ds-index-backend-id";



  /**
   * The name of the attribute that contains the backend base DN.
   */
  @NotNull private static final String ATTR_BASE_DN =
       "ds-index-backend-base-dn";



  /**
   * The name of the attribute that contains the name of the associated
   * attribute type.
   */
  @NotNull private static final String ATTR_INDEX_ATTR =
       "ds-index-attribute-type";



  /**
   * The name of the attribute that contains the name of the associated
   * attribute index type.
   */
  @NotNull private static final String ATTR_INDEX_TYPE = "ds-index-type";



  /**
   * The name of the attribute that contains the string representation of a
   * filter used for the index.
   */
  @NotNull private static final String ATTR_INDEX_FILTER = "ds-index-filter";



  /**
   * The name of the attribute that indicates whether the index is trusted.
   */
  @NotNull private static final String ATTR_INDEX_TRUSTED = "ds-index-trusted";



  /**
   * The name of the attribute that contains the index entry limit.
   */
  @NotNull private static final String ATTR_ENTRY_LIMIT =
       "ds-index-entry-limit";



  /**
   * The name of the attribute that contains the number of index keys for which
   * the entry count has exceeded the limit since the index DB was opened.
   */
  @NotNull private static final String ATTR_EXCEEDED_COUNT =
       "ds-index-exceeded-entry-limit-count-since-db-open";



  /**
   * The name of the attribute that contains the number of unique index keys
   * accessed by search operations that are near (typically, within 80% of) the
   * index entry limit since the index DB was opened.
   */
  @NotNull private static final String ATTR_SEARCH_KEYS_NEAR_LIMIT =
       "ds-index-unique-keys-near-entry-limit-accessed-by-search-since-db-open";



  /**
   * The name of the attribute that contains the number of unique index keys
   * accessed by search operations that are over the index entry limit since the
   * index DB was opened.
   */
  @NotNull private static final String ATTR_SEARCH_KEYS_OVER_LIMIT =
       "ds-index-unique-keys-exceeding-entry-limit-accessed-by-search-since-" +
            "db-open";



  /**
   * The name of the attribute that contains the number of unique index keys
   * accessed by write operations that are near (typically, within 80% of) the
   * index entry limit since the index DB was opened.
   */
  @NotNull private static final String ATTR_WRITE_KEYS_NEAR_LIMIT =
       "ds-index-unique-keys-near-entry-limit-accessed-by-write-since-db-open";



  /**
   * The name of the attribute that contains the number of unique index keys
   * accessed by write operations that are over the index entry limit since the
   * index DB was opened.
   */
  @NotNull private static final String ATTR_WRITE_KEYS_OVER_LIMIT =
       "ds-index-unique-keys-exceeding-entry-limit-accessed-by-write-since-" +
            "db-open";



  /**
   * The name of the attribute that indicates whether a matching count should be
   * maintained for a key that has exceeded the entry limit.
   */
  @NotNull private static final String ATTR_MAINTAIN_COUNT =
       "ds-index-maintain-count";



  /**
   * The name of the attribute that indicates whether the index was fully
   * primed.
   */
  @NotNull private static final String ATTR_FULLY_PRIMED =
       "ds-index-fully-primed-at-backend-open";



  /**
   * The name of the attribute that contains a reason explaining why the prime
   * was not completed.
   */
  @NotNull private static final String ATTR_PRIME_INCOMPLETE_REASON =
       "ds-index-prime-incomplete-reason";



  /**
   * The name of the attribute that contains information about an exception that
   * was encountered while performing the prime.
   */
  @NotNull private static final String ATTR_PRIME_EXCEPTION =
       "ds-index-prime-exception";



  /**
   * The name of the attribute that contains the number of keys that were
   * primed when the backend was opened.
   */
  @NotNull private static final String ATTR_PRIMED_KEYS =
       "ds-index-num-primed-keys-at-backend-open";



  /**
   * The name of the attribute that contains the number of times the index has
   * been updated since the database was opened.
   */
  @NotNull private static final String ATTR_WRITE_COUNT =
       "ds-index-write-count-since-db-open";



  /**
   * The name of the attribute that contains the number of keys deleted from the
   * index since the database was opened.
   */
  @NotNull private static final String ATTR_DELETE_COUNT =
       "ds-index-remove-count-since-db-open";



  /**
   * The name of the attribute that contains the number of read operations
   * against the index since the database was opened.
   */
  @NotNull private static final String ATTR_READ_COUNT =
       "ds-index-read-count-since-db-open";



  /**
   * The name of the attribute that contains the number of read operations
   * performed during search filter evaluation since the database was opened.
   */
  @NotNull private static final String ATTR_READ_FOR_SEARCH_COUNT =
       "ds-index-read-for-search-count-since-db-open";



  /**
   * The name of the attribute that contains the number of cursors created for
   * the index.
   */
  @NotNull private static final String ATTR_CURSOR_COUNT =
       "ds-index-open-cursor-count-since-db-open";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9182830448328951893L;



  // Indicates whether the index was fully primed when the backend came online.
  @Nullable private final Boolean fullyPrimed;

  // Indicates whether the index should be considered trusted.
  @Nullable private final Boolean indexTrusted;

  // Indicates whether to maintain a count of matching entries even when the ID
  // list is not maintained.
  @Nullable private final Boolean maintainCount;

  // The index entry limit for the index.
  @Nullable private final Long entryLimit;

  // The number of keys that have exceeded the entry limit since coming online.
  @Nullable private final Long exceededCount;

  // The number of cursors created in the index since coming online.
  @Nullable private final Long numCursors;

  // The number of index keys deleted from the index since coming online.
  @Nullable private final Long numDeletes;

  // The number of reads from the index since coming online.
  @Nullable private final Long numReads;

  // The number of reads as a result of filter processing from the index since
  // coming online.
  @Nullable private final Long numReadsForSearch;

  // The number of writes to the index since coming online.
  @Nullable private final Long numWrites;

  // The number of keys that were primed when the backend came online.
  @Nullable private final Long primedKeys;

  // The number of keys near the index entry limit that have been accessed by
  // search operations since the index came online.
  @Nullable private final Long searchKeysNearLimit;

  // The number of keys over the index entry limit that have been accessed by
  // search operations since the index came online.
  @Nullable private final Long searchKeysOverLimit;

  // The number of keys near the index entry limit that have been accessed by
  // write operations since the index came online.
  @Nullable private final Long writeKeysNearLimit;

  // The number of keys over the index entry limit that have been accessed by
  // write operations since the index came online.
  @Nullable private final Long writeKeysOverLimit;

  // The name of the associated attribute type.
  @Nullable private final String attributeType;

  // The name of the associated backend ID.
  @Nullable private final String backendID;

  // The base DN for the associated backend.
  @Nullable private final String baseDN;

  // The filter for the associated index.
  @Nullable private final String indexFilter;

  // The index name for the associated index.
  @Nullable private final String indexName;

  // The index name of the index type for the index.
  @Nullable private final String indexType;

  // Information about an exception caught during prime processing.
  @Nullable private final String primeException;

  // Information about the reason the prime was not completed.
  @Nullable private final String primeIncompleteReason;



  /**
   * Creates a new index monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as an index monitor entry.  It must
   *                not be {@code null}.
   */
  public IndexMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    fullyPrimed           = getBoolean(ATTR_FULLY_PRIMED);
    indexTrusted          = getBoolean(ATTR_INDEX_TRUSTED);
    maintainCount         = getBoolean(ATTR_MAINTAIN_COUNT);
    entryLimit            = getLong(ATTR_ENTRY_LIMIT);
    exceededCount         = getLong(ATTR_EXCEEDED_COUNT);
    numCursors            = getLong(ATTR_CURSOR_COUNT);
    numDeletes            = getLong(ATTR_DELETE_COUNT);
    numReads              = getLong(ATTR_READ_COUNT);
    numReadsForSearch     = getLong(ATTR_READ_FOR_SEARCH_COUNT);
    numWrites             = getLong(ATTR_WRITE_COUNT);
    primedKeys            = getLong(ATTR_PRIMED_KEYS);
    searchKeysNearLimit   = getLong(ATTR_SEARCH_KEYS_NEAR_LIMIT);
    searchKeysOverLimit   = getLong(ATTR_SEARCH_KEYS_OVER_LIMIT);
    writeKeysNearLimit    = getLong(ATTR_WRITE_KEYS_NEAR_LIMIT);
    writeKeysOverLimit    = getLong(ATTR_WRITE_KEYS_OVER_LIMIT);
    attributeType         = getString(ATTR_INDEX_ATTR);
    backendID             = getString(ATTR_BACKEND_ID);
    baseDN                = getString(ATTR_BASE_DN);
    indexFilter           = getString(ATTR_INDEX_FILTER);
    indexName             = getString(ATTR_INDEX_NAME);
    indexType             = getString(ATTR_INDEX_TYPE);
    primeException        = getString(ATTR_PRIME_EXCEPTION);
    primeIncompleteReason = getString(ATTR_PRIME_INCOMPLETE_REASON);
  }



  /**
   * Retrieves the name of the index database.
   *
   * @return  The name of the index database, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getIndexName()
  {
    return indexName;
  }



  /**
   * Retrieves the backend ID for the associated backend.
   *
   * @return  The backend ID for the associated backend, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getBackendID()
  {
    return backendID;
  }



  /**
   * Retrieves the base DN for the data with which the index is associated.
   *
   * @return  The base DN for the data with which the index is associated, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the name of the attribute type with which the index is
   * associated.  It will only be available for attribute indexes.
   *
   * @return  The name of the attribute type with which the index is associated,
   *          or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getAttributeType()
  {
    return attributeType;
  }



  /**
   * Retrieves the name of the attribute index type.  It will only be available
   * for attribute indexes.
   *
   * @return  The name of the attribute index type, or {@code null} if it was
   *          not included in the monitor entry.
   */
  @Nullable()
  public String getAttributeIndexType()
  {
    return indexType;
  }



  /**
   * Retrieves the filter used for the index.  It will only be available for
   * filter indexes.
   *
   * @return  The filter used for the index, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getIndexFilter()
  {
    return indexFilter;
  }



  /**
   * Indicates whether the index may be considered trusted.  It will only be
   * available for attribute indexes.
   *
   * @return  {@code true} if the index may be considered trusted,
   *          {@code false} if it is not trusted, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Boolean isIndexTrusted()
  {
    return indexTrusted;
  }



  /**
   * Retrieves the index entry limit, which is the maximum number of entries
   * that will be allowed to match a key before the ID list for that key will
   * stop being maintained.
   *
   * @return  The index entry limit, or {@code null} if was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getIndexEntryLimit()
  {
    return entryLimit;
  }



  /**
   * Retrieves the number of index keys which have stopped being maintained
   * because the number of matching entries has exceeded the entry limit since
   * the index was brought online.
   *
   * @return  The number of index keys which have exceeded the entry limit since
   *          the index was brought online, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getEntryLimitExceededCountSinceComingOnline()
  {
    return exceededCount;
  }



  /**
   * Retrieves the number of unique index keys near (typically, within 80% of)
   * the index entry limit that have been accessed by search operations since
   * the index was brought online.
   *
   * @return  The number of unique index keys near the index entry limit that
   *          have been accessed by search operations since the index was
   *          brought online, or {@code null} if it was not included in the
   *          entry.
   */
  @Nullable()
  public Long getUniqueKeysNearEntryLimitAccessedBySearchSinceComingOnline()
  {
    return searchKeysNearLimit;
  }



  /**
   * Retrieves the number of unique index keys over the index entry limit that
   * have been accessed by search operations since the index was brought online.
   *
   * @return  The number of unique index keys over the index entry limit that
   *          have been accessed by search operations since the index was
   *          brought online, or {@code null} if it was not included in the
   *          entry.
   */
  @Nullable()
  public Long getUniqueKeysOverEntryLimitAccessedBySearchSinceComingOnline()
  {
    return searchKeysOverLimit;
  }



  /**
   * Retrieves the number of unique index keys near (typically, within 80% of)
   * the index entry limit that have been accessed by add, delete, modify, or
   * modify DN operations since the index was brought online.
   *
   * @return  The number of unique index keys near the index entry limit that
   *          have been accessed by write operations since the index was
   *          brought online, or {@code null} if it was not included in the
   *          entry.
   */
  @Nullable()
  public Long getUniqueKeysNearEntryLimitAccessedByWriteSinceComingOnline()
  {
    return writeKeysNearLimit;
  }



  /**
   * Retrieves the number of unique index keys over the index entry limit that
   * have been accessed by add, delete, modify, or modify DN operations since
   * the index was brought online.
   *
   * @return  The number of unique index keys over the index entry limit that
   *          have been accessed by write operations since the index was
   *          brought online, or {@code null} if it was not included in the
   *          entry.
   */
  @Nullable()
  public Long getUniqueKeysOverEntryLimitAccessedByWriteSinceComingOnline()
  {
    return writeKeysOverLimit;
  }



  /**
   * Indicates whether the count of matching entries will be maintained for
   * index keys that have exceeded the entry limit.  In that case, the entry IDs
   * for the matching entries will not be available, but the number of matching
   * entries will be.
   *
   * @return  {@code true} if the count of matching entries will be maintained
   *          for index keys that have exceeded the entry limit, {@code false}
   *          if not, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Boolean maintainCountForExceededKeys()
  {
    return maintainCount;
  }



  /**
   * Indicates whether this index was fully primed when it was brought online.
   *
   * @return  {@code true} if the index was fully primed when it was brought
   *          online, {@code false} if not, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Boolean fullyPrimedWhenBroughtOnline()
  {
    return fullyPrimed;
  }



  /**
   * Retrieves information about the reason that the index was not fully primed
   * when the backend was brought online (e.g., the database cache became full,
   * the prime took too long to complete, or an exception was caught during
   * processing).
   *
   * @return  Information about the reason that the index was not fully primed
   *          when the backend was brought online, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getPrimeIncompleteReason()
  {
    return primeIncompleteReason;
  }



  /**
   * Retrieves information about any exception caught during prime processing.
   *
   * @return  Information about any exception caught during prime processing, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getPrimeException()
  {
    return primeException;
  }



  /**
   * Retrieves the number of index keys that were primed when the index was
   * brought online.
   *
   * @return  The number of index keys that were primed when the backend was
   *          brought online, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getKeysPrimedWhenBroughtOnline()
  {
    return primedKeys;
  }



  /**
   * Retrieves the number of index keys that have been inserted or replaced
   * since the index was brought online.
   *
   * @return  The number of index keys that have been inserted or replaced since
   *          the index was brought online, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public Long getKeysWrittenSinceComingOnline()
  {
    return numWrites;
  }



  /**
   * Retrieves the number of index keys that have been deleted since the index
   * was brought online.
   *
   * @return  The number of index keys that have been deleted since the index
   *          was brought online, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getKeysDeletedSinceComingOnline()
  {
    return numDeletes;
  }



  /**
   * Retrieves the number of index keys that have been read since the index was
   * brought online.
   *
   * @return  The number of index keys that have been read since the index was
   *          brought online, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getKeysReadSinceComingOnline()
  {
    return numReads;
  }



  /**
   * Retrieves the number of index reads that have been initiated because the
   * associated attribute type was included in the filter for a search operation
   * with a non-base scope since the index was brought online.
   *
   * @return  The number of index reads that have been initiated as a result of
   *          filter processing, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getFilterInitiatedReadsSinceComingOnline()
  {
    return numReadsForSearch;
  }



  /**
   * Retrieves the number of cursors created in the index for reading ranges of
   * keys.  Cursors may be used for processing in a variety of contexts,
   * including processing for substring or range searches, subtree deletes,
   * stream values operations, etc.
   *
   * @return  The number of cursors created in the index for reading ranges of
   *          keys, or {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCursorsCreatedSinceComingOnline()
  {
    return numCursors;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_INDEX_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_INDEX_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(19));

    if (indexName != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INDEX_NAME,
           INFO_INDEX_DISPNAME_INDEX_NAME.get(),
           INFO_INDEX_DESC_INDEX_NAME.get(),
           indexName);
    }

    if (backendID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BACKEND_ID,
           INFO_INDEX_DISPNAME_BACKEND_ID.get(),
           INFO_INDEX_DESC_BACKEND_ID.get(),
           backendID);
    }

    if (baseDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_INDEX_DISPNAME_BASE_DN.get(),
           INFO_INDEX_DESC_BASE_DN.get(),
           baseDN);
    }

    if (attributeType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INDEX_ATTR,
           INFO_INDEX_DISPNAME_ATTR_TYPE.get(),
           INFO_INDEX_DESC_ATTR_TYPE.get(),
           attributeType);
    }

    if (indexType != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INDEX_TYPE,
           INFO_INDEX_DISPNAME_INDEX_TYPE.get(),
           INFO_INDEX_DESC_INDEX_TYPE.get(),
           indexType);
    }

    if (indexFilter != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INDEX_FILTER,
           INFO_INDEX_DISPNAME_FILTER.get(),
           INFO_INDEX_DESC_FILTER.get(),
           indexFilter);
    }

    if (indexTrusted != null)
    {
      addMonitorAttribute(attrs,
           ATTR_INDEX_TRUSTED,
           INFO_INDEX_DISPNAME_TRUSTED.get(),
           INFO_INDEX_DESC_TRUSTED.get(),
           indexTrusted);
    }

    if (entryLimit != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ENTRY_LIMIT,
           INFO_INDEX_DISPNAME_ENTRY_LIMIT.get(),
           INFO_INDEX_DESC_ENTRY_LIMIT.get(),
           entryLimit);
    }

    if (exceededCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EXCEEDED_COUNT,
           INFO_INDEX_DISPNAME_EXCEEDED_COUNT.get(),
           INFO_INDEX_DESC_EXCEEDED_COUNT.get(),
           exceededCount);
    }

    if (searchKeysNearLimit != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_KEYS_NEAR_LIMIT,
           INFO_INDEX_DISPNAME_SEARCH_KEYS_NEAR_LIMIT.get(),
           INFO_INDEX_DESC_SEARCH_KEYS_NEAR_LIMIT.get(),
           searchKeysNearLimit);
    }

    if (searchKeysOverLimit != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_KEYS_OVER_LIMIT,
           INFO_INDEX_DISPNAME_SEARCH_KEYS_OVER_LIMIT.get(),
           INFO_INDEX_DESC_SEARCH_KEYS_OVER_LIMIT.get(),
           searchKeysOverLimit);
    }

    if (writeKeysNearLimit != null)
    {
      addMonitorAttribute(attrs,
           ATTR_WRITE_KEYS_NEAR_LIMIT,
           INFO_INDEX_DISPNAME_WRITE_KEYS_NEAR_LIMIT.get(),
           INFO_INDEX_DESC_WRITE_KEYS_NEAR_LIMIT.get(),
           writeKeysNearLimit);
    }

    if (writeKeysOverLimit != null)
    {
      addMonitorAttribute(attrs,
           ATTR_WRITE_KEYS_OVER_LIMIT,
           INFO_INDEX_DISPNAME_WRITE_KEYS_OVER_LIMIT.get(),
           INFO_INDEX_DESC_WRITE_KEYS_OVER_LIMIT.get(),
           writeKeysOverLimit);
    }

    if (maintainCount != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAINTAIN_COUNT,
           INFO_INDEX_DISPNAME_MAINTAIN_COUNT.get(),
           INFO_INDEX_DESC_MAINTAIN_COUNT.get(),
           maintainCount);
    }

    if (fullyPrimed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_FULLY_PRIMED,
           INFO_INDEX_DISPNAME_FULLY_PRIMED.get(),
           INFO_INDEX_DESC_FULLY_PRIMED.get(),
           fullyPrimed);
    }

    if (primeIncompleteReason != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PRIME_INCOMPLETE_REASON,
           INFO_INDEX_DISPNAME_PRIME_INCOMPLETE_REASON.get(),
           INFO_INDEX_DESC_PRIME_INCOMPLETE_REASON.get(),
           primeIncompleteReason);
    }

    if (primeException != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PRIME_EXCEPTION,
           INFO_INDEX_DISPNAME_PRIME_EXCEPTION.get(),
           INFO_INDEX_DESC_PRIME_EXCEPTION.get(),
           primeException);
    }

    if (primedKeys != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PRIMED_KEYS,
           INFO_INDEX_DISPNAME_PRIMED_KEYS.get(),
           INFO_INDEX_DESC_PRIMED_KEYS.get(),
           primedKeys);
    }

    if (numWrites != null)
    {
      addMonitorAttribute(attrs,
           ATTR_WRITE_COUNT,
           INFO_INDEX_DISPNAME_WRITE_COUNT.get(),
           INFO_INDEX_DESC_WRITE_COUNT.get(),
           numWrites);
    }

    if (numDeletes != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_COUNT,
           INFO_INDEX_DISPNAME_DELETE_COUNT.get(),
           INFO_INDEX_DESC_DELETE_COUNT.get(),
           numDeletes);
    }

    if (numReads != null)
    {
      addMonitorAttribute(attrs,
           ATTR_READ_COUNT,
           INFO_INDEX_DISPNAME_READ_COUNT.get(),
           INFO_INDEX_DESC_READ_COUNT.get(),
           numReads);
    }

    if (numReadsForSearch != null)
    {
      addMonitorAttribute(attrs,
           ATTR_READ_FOR_SEARCH_COUNT,
           INFO_INDEX_DISPNAME_FILTER_INITIATED_READ_COUNT.get(),
           INFO_INDEX_DESC_FILTER_INITIATED_READ_COUNT.get(),
           numReadsForSearch);
    }

    if (numCursors != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURSOR_COUNT,
           INFO_INDEX_DISPNAME_CURSOR_COUNT.get(),
           INFO_INDEX_DESC_CURSOR_COUNT.get(),
           numCursors);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
