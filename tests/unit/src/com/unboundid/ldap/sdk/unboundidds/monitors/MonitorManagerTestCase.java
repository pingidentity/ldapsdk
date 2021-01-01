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



import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the MonitorManager class.
 */
public class MonitorManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<MonitorEntry> monitorEntries = MonitorManager.getMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (MonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getGeneralMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGeneralMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    GeneralMonitorEntry e = MonitorManager.getGeneralMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());

    assertNotNull(e.getCurrentConnections());

    assertNotNull(e.getMaxConnections());

    assertNotNull(e.getTotalConnections());

    assertNotNull(e.getCurrentTime());

    assertNotNull(e.getStartTime());

    assertNotNull(e.getStartupUUID());

    assertNotNull(e.getUptimeMillis());

    assertNotNull(e.getUptimeString());

    assertNotNull(e.getProductName());

    assertNotNull(e.getVendorName());

    assertNotNull(e.getVersionString());

    conn.close();
  }



  /**
   * Tests the {@code getActiveOperationsMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetActiveOperationsMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    ActiveOperationsMonitorEntry e =
         MonitorManager.getActiveOperationsMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());

    assertNotNull(e.getActiveOperations());
    assertFalse(e.getActiveOperations().isEmpty());

    conn.close();
  }



  /**
   * Tests the {@code getBackendMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBackendMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<BackendMonitorEntry> monitorEntries =
         MonitorManager.getBackendMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (BackendMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getBackendID());

      assertNotNull(e.getBaseDNs());
      assertFalse(e.getBaseDNs().isEmpty());

      assertNotNull(e.isPrivate());

      assertNotNull(e.getWritabilityMode());

      assertNotNull(e.getTotalEntries());

      assertNotNull(e.getEntriesPerBaseDN());
      assertEquals(e.getEntriesPerBaseDN().size(),
                   e.getBaseDNs().size());
    }

    conn.close();
  }



  /**
   * Tests the {@code getClientConnectionMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetClientConnectionMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    ClientConnectionMonitorEntry e =
         MonitorManager.getClientConnectionMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());

    assertNotNull(e.getConnections());
    assertFalse(e.getConnections().isEmpty());

    conn.close();
  }



  /**
   * Tests the {@code getConnectionHandlerMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionHandlerMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<ConnectionHandlerMonitorEntry> monitorEntries =
         MonitorManager.getConnectionHandlerMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (ConnectionHandlerMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getConnections());

      // This may be nonexistent for some connection handlers.
      e.getListeners();

      assertNotNull(e.getNumConnections());

      assertNotNull(e.getProtocol());
    }

    conn.close();
  }



  /**
   * Tests the {@code getDiskSpaceUsageMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDiskSpaceUsageMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    DiskSpaceUsageMonitorEntry e =
         MonitorManager.getDiskSpaceUsageMonitorEntry(conn);

    assertNotNull(e);

    assertNotNull(e.getCurrentState());

    assertNotNull(e.getDiskSpaceInfo());
    assertFalse(e.getDiskSpaceInfo().isEmpty());

    conn.close();
  }



  /**
   * Tests the {@code getEntryCacheMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryCacheMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    EntryCacheMonitorEntry e =
         MonitorManager.getEntryCacheMonitorEntry(conn);

    // If the entry cache is completely disabled, then there may not be a
    // monitor entry.
    if (e != null)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      // Any of these values may be null, so we'll just get coverage for them.
      e.getCacheTries();
      e.getCacheHits();
      e.getCacheMisses();
      e.getCacheHitRatio();
      e.getCurrentCount();
      e.getMaxCount();
      e.getCurrentCacheSize();
      e.getMaxCacheSize();
    }

    conn.close();
  }



  /**
   * Tests the {@code getFIFOEntryCacheMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFIFOEntryCacheMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<FIFOEntryCacheMonitorEntry> monitorEntries =
         MonitorManager.getFIFOEntryCacheMonitorEntries(conn);
    assertNotNull(monitorEntries);

    for (FIFOEntryCacheMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getCacheName());

      e.getCapacityDetails();
    }

    conn.close();
  }



  /**
   * Tests the {@code getGaugeMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGaugeMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    final List<GaugeMonitorEntry> l =
         MonitorManager.getGaugeMonitorEntries(conn);
    assertNotNull(l);

    for (final GaugeMonitorEntry e : l)
    {
      assertTrue((e instanceof NumericGaugeMonitorEntry) ||
           (e instanceof IndicatorGaugeMonitorEntry));

      assertNotNull(e.getGaugeName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getGroupCacheMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetGroupCacheMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    GroupCacheMonitorEntry e =
         MonitorManager.getGroupCacheMonitorEntry(conn);
    if (e != null)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getGroupCacheMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHostSystemRecentCPUAndMemoryMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    HostSystemRecentCPUAndMemoryMonitorEntry e =
         MonitorManager.getHostSystemRecentCPUAndMemoryMonitorEntry(conn);
    if (e != null)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getIndexMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIndexMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<IndexMonitorEntry> monitorEntries =
         MonitorManager.getIndexMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (IndexMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getIndexName());

      assertNotNull(e.getBackendID());
    }

    conn.close();
  }



  /**
   * Tests the {@code getIndicatorGaugeMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIndicatorGaugeMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final List<IndicatorGaugeMonitorEntry> l =
         MonitorManager.getIndicatorGaugeMonitorEntries(conn);
    assertNotNull(l);

    for (final GaugeMonitorEntry e : l)
    {
      assertNotNull(e.getGaugeName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getJEEnvironmentMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetJEEnvironmentMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<JEEnvironmentMonitorEntry> monitorEntries =
         MonitorManager.getJEEnvironmentMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (JEEnvironmentMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getBackendID());

      assertNotNull(e.getJEVersion());
    }

    conn.close();
  }



  /**
   * Tests the {@code getLDAPExternalServerMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPExternalServerMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<LDAPExternalServerMonitorEntry> monitorEntries =
         MonitorManager.getLDAPExternalServerMonitorEntries(conn);
    assertNotNull(monitorEntries);

    // These monitor entries generally won't be present in the target Directory
    // Server since they are more intended for use in the Directory Proxy
    // Server so no further checks can be performed.

    conn.close();
  }



  /**
   * Tests the {@code getLDAPStatisticsMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPStatisticsMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<LDAPStatisticsMonitorEntry> monitorEntries =
         MonitorManager.getLDAPStatisticsMonitorEntries(conn);
    assertNotNull(monitorEntries);
    assertFalse(monitorEntries.isEmpty());

    for (LDAPStatisticsMonitorEntry e : monitorEntries)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getConnectionsEstablished());
      assertNotNull(e.getConnectionsClosed());

      assertNotNull(e.getOperationsInitiated());
      assertNotNull(e.getOperationsCompleted());
      assertNotNull(e.getOperationsAbandoned());

      assertNotNull(e.getBytesRead());
      assertNotNull(e.getBytesWritten());
      assertNotNull(e.getLDAPMessagesRead());
      assertNotNull(e.getLDAPMessagesWritten());

      assertNotNull(e.getAbandonRequests());

      assertNotNull(e.getAddRequests());
      assertNotNull(e.getAddResponses());

      assertNotNull(e.getBindRequests());
      assertNotNull(e.getBindResponses());

      assertNotNull(e.getCompareRequests());
      assertNotNull(e.getCompareResponses());

      assertNotNull(e.getDeleteRequests());
      assertNotNull(e.getDeleteResponses());

      assertNotNull(e.getExtendedRequests());
      assertNotNull(e.getExtendedResponses());

      assertNotNull(e.getModifyRequests());
      assertNotNull(e.getModifyResponses());

      assertNotNull(e.getModifyDNRequests());
      assertNotNull(e.getModifyDNResponses());

      assertNotNull(e.getSearchRequests());
      assertNotNull(e.getSearchResultEntries());
      assertNotNull(e.getSearchResultReferences());
      assertNotNull(e.getSearchDoneResponses());

      assertNotNull(e.getUnbindRequests());
    }

    conn.close();
  }



  /**
   * Tests the {@code getLoadBalancingAlgorithmMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLoadBalancingAlgorithmMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<LoadBalancingAlgorithmMonitorEntry> monitorEntries =
         MonitorManager.getLoadBalancingAlgorithmMonitorEntries(conn);
    assertNotNull(monitorEntries);

    // These monitor entries generally won't be present in the target Directory
    // Server since they are more intended for use in the Directory Proxy
    // Server so no further checks can be performed.

    conn.close();
  }



  /**
   * Tests the {@code getMemoryUsageMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMemoryUsageMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    MemoryUsageMonitorEntry e =
         MonitorManager.getMemoryUsageMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());


    // Get the names of the garbage collectors, and then iterate through them
    // to get the collection counts and durations.
    List<String> gcNames = e.getGarbageCollectorNames();
    assertNotNull(gcNames);
    assertFalse(gcNames.isEmpty());

    assertNotNull(e.getTotalCollectionCounts());
    assertNotNull(e.getTotalCollectionDurations());
    assertNotNull(e.getAverageCollectionDurations());
    assertNotNull(e.getRecentCollectionDurations());

    for (String gcName : gcNames)
    {
      assertNotNull(e.getTotalCollectionCount(gcName));
      assertNotNull(e.getTotalCollectionDuration(gcName));
      assertNotNull(e.getAverageCollectionDuration(gcName));
      assertNotNull(e.getRecentCollectionDuration(gcName));
    }


    // Get the names of the memory pools and then iterate through them to get
    // the memory used.
    List<String> mpNames = e.getMemoryPoolNames();
    assertNotNull(mpNames);
    assertFalse(mpNames.isEmpty());

    assertNotNull(e.getCurrentBytesUsed());
    assertNotNull(e.getBytesUsedAfterLastCollection());

    for (String mpName : mpNames)
    {
      assertNotNull(e.getCurrentBytesUsed(mpName));
      assertNotNull(e.getBytesUsedAfterLastCollection(mpName));
    }

    conn.close();
  }



  /**
   * Tests the {@code getNumericGaugeMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNumericGaugeMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final List<NumericGaugeMonitorEntry> l =
         MonitorManager.getNumericGaugeMonitorEntries(conn);
    assertNotNull(l);

    for (final GaugeMonitorEntry e : l)
    {
      assertNotNull(e.getGaugeName());
    }

    conn.close();
  }



  /**
   * Tests the {@code getProcessingTimeHistogramMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetProcessingTimeHistogramMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    ProcessingTimeHistogramMonitorEntry e =
         MonitorManager.getProcessingTimeHistogramMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());


    assertNotNull(e.getAllOpsCount());
    assertFalse(e.getAllOpsCount().isEmpty());
    int numBuckets = e.getAllOpsCount().size();
    assertTrue(numBuckets >= 3);

    assertNotNull(e.getAllOpsPercent());
    assertFalse(e.getAllOpsPercent().isEmpty());
    assertEquals(e.getAllOpsPercent().size(), numBuckets);

    assertNotNull(e.getAllOpsAggregatePercent());
    assertFalse(e.getAllOpsAggregatePercent().isEmpty());
    assertEquals(e.getAllOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getAddOpsCount());
    assertFalse(e.getAddOpsCount().isEmpty());
    assertEquals(e.getAddOpsCount().size(), numBuckets);

    assertNotNull(e.getAddOpsPercent());
    assertFalse(e.getAddOpsPercent().isEmpty());
    assertEquals(e.getAddOpsPercent().size(), numBuckets);

    assertNotNull(e.getAddOpsAggregatePercent());
    assertFalse(e.getAddOpsAggregatePercent().isEmpty());
    assertEquals(e.getAddOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getBindOpsCount());
    assertFalse(e.getBindOpsCount().isEmpty());
    assertEquals(e.getBindOpsCount().size(), numBuckets);

    assertNotNull(e.getBindOpsPercent());
    assertFalse(e.getBindOpsPercent().isEmpty());
    assertEquals(e.getBindOpsPercent().size(), numBuckets);

    assertNotNull(e.getBindOpsAggregatePercent());
    assertFalse(e.getBindOpsAggregatePercent().isEmpty());
    assertEquals(e.getBindOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getCompareOpsCount());
    assertFalse(e.getCompareOpsCount().isEmpty());
    assertEquals(e.getCompareOpsCount().size(), numBuckets);

    assertNotNull(e.getCompareOpsPercent());
    assertFalse(e.getCompareOpsPercent().isEmpty());
    assertEquals(e.getCompareOpsPercent().size(), numBuckets);

    assertNotNull(e.getCompareOpsAggregatePercent());
    assertFalse(e.getCompareOpsAggregatePercent().isEmpty());
    assertEquals(e.getCompareOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getDeleteOpsCount());
    assertFalse(e.getDeleteOpsCount().isEmpty());
    assertEquals(e.getDeleteOpsCount().size(), numBuckets);

    assertNotNull(e.getDeleteOpsPercent());
    assertFalse(e.getDeleteOpsPercent().isEmpty());
    assertEquals(e.getDeleteOpsPercent().size(), numBuckets);

    assertNotNull(e.getDeleteOpsAggregatePercent());
    assertFalse(e.getDeleteOpsAggregatePercent().isEmpty());
    assertEquals(e.getDeleteOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getModifyOpsCount());
    assertFalse(e.getModifyOpsCount().isEmpty());
    assertEquals(e.getModifyOpsCount().size(), numBuckets);

    assertNotNull(e.getModifyOpsPercent());
    assertFalse(e.getModifyOpsPercent().isEmpty());
    assertEquals(e.getModifyOpsPercent().size(), numBuckets);

    assertNotNull(e.getModifyOpsAggregatePercent());
    assertFalse(e.getModifyOpsAggregatePercent().isEmpty());
    assertEquals(e.getModifyOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getModifyDNOpsCount());
    assertFalse(e.getModifyDNOpsCount().isEmpty());
    assertEquals(e.getModifyDNOpsCount().size(), numBuckets);

    assertNotNull(e.getModifyDNOpsPercent());
    assertFalse(e.getModifyDNOpsPercent().isEmpty());
    assertEquals(e.getModifyDNOpsPercent().size(), numBuckets);

    assertNotNull(e.getModifyDNOpsAggregatePercent());
    assertFalse(e.getModifyDNOpsAggregatePercent().isEmpty());
    assertEquals(e.getModifyDNOpsAggregatePercent().size(), numBuckets);

    assertNotNull(e.getSearchOpsCount());
    assertFalse(e.getSearchOpsCount().isEmpty());
    assertEquals(e.getSearchOpsCount().size(), numBuckets);

    assertNotNull(e.getSearchOpsPercent());
    assertFalse(e.getSearchOpsPercent().isEmpty());
    assertEquals(e.getSearchOpsPercent().size(), numBuckets);

    assertNotNull(e.getSearchOpsAggregatePercent());
    assertFalse(e.getSearchOpsAggregatePercent().isEmpty());
    assertEquals(e.getSearchOpsAggregatePercent().size(), numBuckets);

    conn.close();
  }



  /**
   * Tests the {@code getPerApplicationProcessingTimeHistogramMonitorEntries}
   * method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPerApplicationProcessingTimeHistogramMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final List<PerApplicationProcessingTimeHistogramMonitorEntry> l =
         MonitorManager.getPerApplicationProcessingTimeHistogramMonitorEntries(
              conn);
    assertNotNull(l);

    for (final PerApplicationProcessingTimeHistogramMonitorEntry e : l)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());
      assertNotNull(e.getApplicationName());

      assertNotNull(e.getAllOpsCount());
      assertFalse(e.getAllOpsCount().isEmpty());
      final int numBuckets = e.getAllOpsCount().size();
      assertTrue(numBuckets >= 3);

      assertNotNull(e.getAllOpsPercent());
      assertFalse(e.getAllOpsPercent().isEmpty());
      assertEquals(e.getAllOpsPercent().size(), numBuckets);

      assertNotNull(e.getAllOpsAggregatePercent());
      assertFalse(e.getAllOpsAggregatePercent().isEmpty());
      assertEquals(e.getAllOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getAddOpsCount());
      assertFalse(e.getAddOpsCount().isEmpty());
      assertEquals(e.getAddOpsCount().size(), numBuckets);

      assertNotNull(e.getAddOpsPercent());
      assertFalse(e.getAddOpsPercent().isEmpty());
      assertEquals(e.getAddOpsPercent().size(), numBuckets);

      assertNotNull(e.getAddOpsAggregatePercent());
      assertFalse(e.getAddOpsAggregatePercent().isEmpty());
      assertEquals(e.getAddOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getBindOpsCount());
      assertFalse(e.getBindOpsCount().isEmpty());
      assertEquals(e.getBindOpsCount().size(), numBuckets);

      assertNotNull(e.getBindOpsPercent());
      assertFalse(e.getBindOpsPercent().isEmpty());
      assertEquals(e.getBindOpsPercent().size(), numBuckets);

      assertNotNull(e.getBindOpsAggregatePercent());
      assertFalse(e.getBindOpsAggregatePercent().isEmpty());
      assertEquals(e.getBindOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getCompareOpsCount());
      assertFalse(e.getCompareOpsCount().isEmpty());
      assertEquals(e.getCompareOpsCount().size(), numBuckets);

      assertNotNull(e.getCompareOpsPercent());
      assertFalse(e.getCompareOpsPercent().isEmpty());
      assertEquals(e.getCompareOpsPercent().size(), numBuckets);

      assertNotNull(e.getCompareOpsAggregatePercent());
      assertFalse(e.getCompareOpsAggregatePercent().isEmpty());
      assertEquals(e.getCompareOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getDeleteOpsCount());
      assertFalse(e.getDeleteOpsCount().isEmpty());
      assertEquals(e.getDeleteOpsCount().size(), numBuckets);

      assertNotNull(e.getDeleteOpsPercent());
      assertFalse(e.getDeleteOpsPercent().isEmpty());
      assertEquals(e.getDeleteOpsPercent().size(), numBuckets);

      assertNotNull(e.getDeleteOpsAggregatePercent());
      assertFalse(e.getDeleteOpsAggregatePercent().isEmpty());
      assertEquals(e.getDeleteOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getModifyOpsCount());
      assertFalse(e.getModifyOpsCount().isEmpty());
      assertEquals(e.getModifyOpsCount().size(), numBuckets);

      assertNotNull(e.getModifyOpsPercent());
      assertFalse(e.getModifyOpsPercent().isEmpty());
      assertEquals(e.getModifyOpsPercent().size(), numBuckets);

      assertNotNull(e.getModifyOpsAggregatePercent());
      assertFalse(e.getModifyOpsAggregatePercent().isEmpty());
      assertEquals(e.getModifyOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getModifyDNOpsCount());
      assertFalse(e.getModifyDNOpsCount().isEmpty());
      assertEquals(e.getModifyDNOpsCount().size(), numBuckets);

      assertNotNull(e.getModifyDNOpsPercent());
      assertFalse(e.getModifyDNOpsPercent().isEmpty());
      assertEquals(e.getModifyDNOpsPercent().size(), numBuckets);

      assertNotNull(e.getModifyDNOpsAggregatePercent());
      assertFalse(e.getModifyDNOpsAggregatePercent().isEmpty());
      assertEquals(e.getModifyDNOpsAggregatePercent().size(), numBuckets);

      assertNotNull(e.getSearchOpsCount());
      assertFalse(e.getSearchOpsCount().isEmpty());
      assertEquals(e.getSearchOpsCount().size(), numBuckets);

      assertNotNull(e.getSearchOpsPercent());
      assertFalse(e.getSearchOpsPercent().isEmpty());
      assertEquals(e.getSearchOpsPercent().size(), numBuckets);

      assertNotNull(e.getSearchOpsAggregatePercent());
      assertFalse(e.getSearchOpsAggregatePercent().isEmpty());
      assertEquals(e.getSearchOpsAggregatePercent().size(), numBuckets);
    }

    conn.close();
  }



  /**
   * Tests the {@code getReplicaMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReplicaMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<ReplicaMonitorEntry> monitorEntries =
         MonitorManager.getReplicaMonitorEntries(conn);
    assertNotNull(monitorEntries);

    // In environments without replication configured, this will often be
    // empty so we can't do much more testing.

    conn.close();
  }



  /**
   * Tests the {@code getReplicationServerMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReplicationServerMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    ReplicationServerMonitorEntry e =
         MonitorManager.getReplicationServerMonitorEntry(conn);

    // In environments without replication configured, this will often be
    // empty so we can't do much more testing.

    conn.close();
  }



  /**
   * Tests the {@code getReplicationSummaryMonitorEntries} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReplicationSummaryMonitorEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    List<ReplicationSummaryMonitorEntry> monitorEntries =
         MonitorManager.getReplicationSummaryMonitorEntries(conn);
    assertNotNull(monitorEntries);

    // In environments without replication configured, this will often be
    // empty so we can't do much more testing.

    conn.close();
  }



  /**
   * Tests the {@code getResultCodeMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetResultCodeMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    final ResultCodeMonitorEntry monitorEntry =
         MonitorManager.getResultCodeMonitorEntry(conn);
    if (monitorEntry != null)
    {
      assertNotNull(monitorEntry.getAllOperationsResultCodeInfo());
    }

    conn.close();
  }



  /**
   * Tests the {@code getSystemInfoMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSystemInfoMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SystemInfoMonitorEntry e = MonitorManager.getSystemInfoMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());


    assertNotNull(e.getAvailableCPUs());
    assertTrue(e.getAvailableCPUs() >= 1);

    assertNotNull(e.getClassPath());

    assertNotNull(e.getFreeMemory());
    assertTrue(e.getFreeMemory() > 0);

    assertNotNull(e.getHostname());

    assertNotNull(e.getInstanceRoot());

    assertNotNull(e.getJavaHome());

    assertNotNull(e.getJavaVendor());

    assertNotNull(e.getJavaVersion());

    assertNotNull(e.getJVMArchitectureDataModel());

    assertNotNull(e.getJVMArguments());

    assertNotNull(e.getJVMVendor());

    assertNotNull(e.getJVMVersion());

    assertNotNull(e.getMaxMemory());

    assertNotNull(e.getOperatingSystem());

    assertNotNull(e.getUsedMemory());

    assertNotNull(e.getWorkingDirectory());

    conn.close();
  }



  /**
   * Tests the {@code getStackTraceMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStackTraceMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    StackTraceMonitorEntry e = MonitorManager.getStackTraceMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());

    assertNotNull(e.getStackTraces());
    assertFalse(e.getStackTraces().isEmpty());

    for (ThreadStackTrace t : e.getStackTraces())
    {
      assertNotNull(t.getThreadID());
      assertNotNull(t.getThreadName());
      assertNotNull(t.getStackTraceElements());
    }

    conn.close();
  }



  /**
   * Tests the {@code getTraditionalWorkQueueMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetTraditionalWorkQueueMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    TraditionalWorkQueueMonitorEntry e =
         MonitorManager.getTraditionalWorkQueueMonitorEntry(conn);
    if (e != null)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getRequestsSubmitted());
      assertNotNull(e.getRequestsRejectedDueToQueueFull());
      assertNotNull(e.getCurrentBacklog());
      assertNotNull(e.getAverageBacklog());
    }

    conn.close();
  }



  /**
   * Tests the {@code getUnboundIDWorkQueueMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetUnboundIDWorkQueueMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    UnboundIDWorkQueueMonitorEntry e =
         MonitorManager.getUnboundIDWorkQueueMonitorEntry(conn);
    if (e != null)
    {
      assertNotNull(e.getEntry());
      assertNotNull(e.getMonitorClass());
      assertNotNull(e.getMonitorName());

      assertNotNull(e.getRequestsRejectedDueToQueueFull());
      assertNotNull(e.getCurrentSize());
      assertNotNull(e.getAverageSize());
    }

    conn.close();
  }



  /**
   * Tests the {@code getVersionMonitorEntry} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetVersionMonitorEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    VersionMonitorEntry e = MonitorManager.getVersionMonitorEntry(conn);
    assertNotNull(e);

    assertNotNull(e.getEntry());
    assertNotNull(e.getMonitorClass());
    assertNotNull(e.getMonitorName());

    assertNotNull(e.getBuildID());

    assertNotNull(e.getCompactVersion());

    assertNotNull(e.getFullVersion());

    assertNotNull(e.getMajorVersion());

    assertNotNull(e.getMinorVersion());

    assertNotNull(e.getPointVersion());

    assertNotNull(e.getProductName());

    assertNotNull(e.getRevisionID());

    assertNotNull(e.getShortProductName());

    // These may or may not be null based on the build being tested.
    e.getBuildNumber();
    e.getFixIDs();
    e.getVersionQualifier();

    conn.close();
  }
}
