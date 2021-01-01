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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the state
 * of a replica, including the base DN, replica ID, and generation ID, as well
 * as information about its communication with the replication server
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
 * The server should present a replica monitor entry for each replicated base
 * DN.  They can be retrieved using the
 * {@link MonitorManager#getReplicaMonitorEntries} method.  These entries
 * provide specific methods for accessing information about the replica.
 * Alternately, this information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicaMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in replica monitor entries.
   */
  @NotNull static final String REPLICA_MONITOR_OC =
       "ds-replica-monitor-entry";



  /**
   * The name of the attribute that contains the base DNs for the replicated
   * data.
   */
  @NotNull private static final String ATTR_BASE_DN = "base-dn";



  /**
   * The name of the attribute that contains the address and port of the
   * replication server to which the replica is connected.
   */
  @NotNull private static final String ATTR_CONNECTED_TO =
       "connected-to";



  /**
   * The name of the attribute that provides information about the current
   * receive window size.
   */
  @NotNull private static final String ATTR_CURRENT_RECEIVE_WINDOW_SIZE =
       "current-rcv-window";



  /**
   * The name of the attribute that provides information about the current send
   * window size.
   */
  @NotNull private static final String ATTR_CURRENT_SEND_WINDOW_SIZE =
       "current-send-window";



  /**
   * The name of the attribute that provides the generation ID for the replica.
   */
  @NotNull private static final String ATTR_GENERATION_ID = "generation-id";



  /**
   * The name of the attribute that provides information about the number of
   * times the connection to the replication server has been lost.
   */
  @NotNull private static final String ATTR_LOST_CONNECTIONS =
       "lost-connections";



  /**
   * The name of the attribute that provides information about the maximum
   * receive window size.
   */
  @NotNull private static final String ATTR_MAX_RECEIVE_WINDOW_SIZE =
       "max-rcv-window";



  /**
   * The name of the attribute that provides information about the maximum send
   * window size.
   */
  @NotNull private static final String ATTR_MAX_SEND_WINDOW_SIZE =
       "max-send-window";



  /**
   * The name of the attribute that provides information about the number of
   * pending updates which are currently being processed by the Directory Server
   * and have not yet been sent to the replication server.
   */
  @NotNull private static final String ATTR_PENDING_UPDATES = "pending-updates";



  /**
   * The name of the attribute that provides information about the number of
   * updates received from the replication server for this replica.
   */
  @NotNull private static final String ATTR_RECEIVED_UPDATES =
       "received-updates";



  /**
   * The name of the attribute that provides the replica ID for this replica.
   */
  @NotNull private static final String ATTR_REPLICA_ID = "replica-id";



  /**
   * The name of the attribute that provides information about the number of
   * updates that were replayed after resolving a modify conflict.
   */
  @NotNull private static final String ATTR_RESOLVED_MODIFY_CONFLICTS =
       "resolved-modify-conflicts";



  /**
   * The name of the attribute that provides information about the number of
   * updates that were replayed after resolving a naming conflict.
   */
  @NotNull private static final String ATTR_RESOLVED_NAMING_CONFLICTS =
       "resolved-naming-conflicts";



  /**
   * The name of the attribute that provides information about the number of
   * updates sent to the replication server from this replica.
   */
  @NotNull private static final String ATTR_SENT_UPDATES = "sent-updates";



  /**
   * The name of the attribute that indicates whether SSL is used when
   * communicating with the replication server.
   */
  @NotNull private static final String ATTR_SSL_ENCRYPTION = "ssl-encryption";



  /**
   * The name of the attribute that provides information about the number of
   * updates that have been successfully replayed with no problems.
   */
  @NotNull private static final String ATTR_SUCCESSFUL_REPLAYED =
       "replayed-updates-ok";



  /**
   * The name of the attribute that provides information about the total number
   * of updates that have been replayed in some form.
   */
  @NotNull private static final String ATTR_TOTAL_REPLAYED = "replayed-updates";



  /**
   * The name of the attribute that provides information about the number of
   * updates that could not be replayed because of an unresolved naming
   * conflict.
   */
  @NotNull private static final String ATTR_UNRESOLVED_NAMING_CONFLICTS =
       "unresolved-naming-conflicts";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9164207693317460579L;



  // Indicates whether the replica uses SSL when communicating with the
  // replication server.
  @Nullable private final Boolean useSSL;

  // The current receive window size.
  @Nullable private final Long currentReceiveWindowSize;

  // The current send window size.
  @Nullable private final Long currentSendWindowSize;

  // The number of lost connections.
  @Nullable private final Long lostConnections;

  // The maximum receive window size.
  @Nullable private final Long maxReceiveWindowSize;

  // The maximum send window size.
  @Nullable private final Long maxSendWindowSize;

  // The number of pending updates that haven't been sent to the replication
  // server.
  @Nullable private final Long pendingUpdates;

  // The number of updates received from the replication server.
  @Nullable private final Long receivedUpdates;

  // The number of updates replayed after resolving a modify conflict.
  @Nullable private final Long replayedAfterModifyConflict;

  // The number of updates replayed after resolving a naming conflict.
  @Nullable private final Long replayedAfterNamingConflict;

  // The port number of the replication server.
  @Nullable private final Long replicationServerPort;

  // The number of updates sent to the replication server.
  @Nullable private final Long sentUpdates;

  // The number of updates replayed successfully.
  @Nullable private final Long successfullyReplayed;

  // The total number of updates replayed.
  @Nullable private final Long totalReplayed;

  // The number of unresolved naming conflicts that could not be successfully
  // replayed.
  @Nullable private final Long unresolvedNamingConflicts;

  // The base DN for the replicated data.
  @Nullable private final String baseDN;

  // The generation ID for the replicated data.
  @Nullable private final String generationID;

  // The replica ID for the replica.
  @Nullable private final String replicaID;

  // The address of the replication server.
  @Nullable private final String replicationServerAddress;



  /**
   * Creates a new replica monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a replica monitor entry.  It must
   *                not be {@code null}.
   */
  public ReplicaMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    useSSL                      = getBoolean(ATTR_SSL_ENCRYPTION);
    lostConnections             = getLong(ATTR_LOST_CONNECTIONS);
    receivedUpdates             = getLong(ATTR_RECEIVED_UPDATES);
    sentUpdates                 = getLong(ATTR_SENT_UPDATES);
    pendingUpdates              = getLong(ATTR_PENDING_UPDATES);
    totalReplayed               = getLong(ATTR_TOTAL_REPLAYED);
    successfullyReplayed        = getLong(ATTR_SUCCESSFUL_REPLAYED);
    replayedAfterModifyConflict = getLong(ATTR_RESOLVED_MODIFY_CONFLICTS);
    replayedAfterNamingConflict = getLong(ATTR_RESOLVED_NAMING_CONFLICTS);
    unresolvedNamingConflicts   = getLong(ATTR_UNRESOLVED_NAMING_CONFLICTS);
    currentReceiveWindowSize    = getLong(ATTR_CURRENT_RECEIVE_WINDOW_SIZE);
    currentSendWindowSize       = getLong(ATTR_CURRENT_SEND_WINDOW_SIZE);
    maxReceiveWindowSize        = getLong(ATTR_MAX_RECEIVE_WINDOW_SIZE);
    maxSendWindowSize           = getLong(ATTR_MAX_SEND_WINDOW_SIZE);
    baseDN                      = getString(ATTR_BASE_DN);
    generationID                = getString(ATTR_GENERATION_ID);
    replicaID                   = getString(ATTR_REPLICA_ID);

    String addr = null;
    Long   port = null;
    final String connectedTo = getString(ATTR_CONNECTED_TO);
    if (connectedTo != null)
    {
      try
      {
        final int colonPos = connectedTo.indexOf(':');
        if (colonPos > 0)
        {
          addr = connectedTo.substring(0, colonPos);
          port = Long.parseLong(connectedTo.substring(colonPos+1));
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        addr = null;
        port = null;
      }
    }

    replicationServerAddress = addr;
    replicationServerPort    = port;
  }



  /**
   * Retrieves the base DN for this replica.
   *
   * @return  The base DN for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the replica ID for this replica.
   *
   * @return  The replica ID for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getReplicaID()
  {
    return replicaID;
  }



  /**
   * Retrieves the generation ID for this replica.
   *
   * @return  The generation ID for this replica, or {@code null} if it was not
   *          included in the monitor entry.
   */
  @Nullable()
  public String getGenerationID()
  {
    return generationID;
  }



  /**
   * Retrieves the address of the replication server to which this replica is
   * connected.
   *
   * @return  The address of the replication server to which this replica is
   *          connected, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public String getReplicationServerAddress()
  {
    return replicationServerAddress;
  }



  /**
   * Retrieves the port number of the replication server to which this replica
   * is connected.
   *
   * @return  The port number of the replication server to which this replica is
   *          connected, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getReplicationServerPort()
  {
    return replicationServerPort;
  }



  /**
   * Indicates whether this replica uses SSL when communicating with the
   * replication server.
   *
   * @return  {@code Boolean.TRUE} if this replica uses SSL when communicating
   *          with the replication server, {@code Boolean.FALSE} if it does not
   *          use SSL, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Boolean useSSL()
  {
    return useSSL;
  }



  /**
   * Retrieves the number of times this replica has lost the connection to a
   * replication server.
   *
   * @return  The number of times this replica has lost the connection to a
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getLostConnections()
  {
    return lostConnections;
  }



  /**
   * Retrieves the number of updates that this replica has received from the
   * replication server.
   *
   * @return  The number of updates that this replica has received from the
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getReceivedUpdates()
  {
    return receivedUpdates;
  }



  /**
   * Retrieves the number of updates that this replica has sent to the
   * replication server.
   *
   * @return  The number of updates that this replica has sent to the
   *          replication server, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getSentUpdates()
  {
    return sentUpdates;
  }



  /**
   * Retrieves the number of updates that are currently in progress in the
   * Directory Server and have not yet been sent to the replication server.
   *
   * @return  The number of updates that are currently in progress in the
   *          Directory Server and have not yet been sent to the replication
   *          server, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getPendingUpdates()
  {
    return pendingUpdates;
  }



  /**
   * Retrieves the total number of updates that have been replayed in this
   * replica.
   *
   * @return  The total number of updates that have been replayed in this
   *          replica, or {@code null} if it was not included in the monitor
   *          entry.
   */
  @Nullable()
  public Long getTotalUpdatesReplayed()
  {
    return totalReplayed;
  }



  /**
   * Retrieves the number of updates that have been successfully replayed in
   * this replica without conflicts.
   *
   * @return  The number of updates that have been successfully replayed in this
   *          replica without conflicts, or {@code null} if it was not included
   *          in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesSuccessfullyReplayed()
  {
    return successfullyReplayed;
  }



  /**
   * Retrieves the number of updates that have been replayed in this replica
   * after automatically resolving a modify conflict.
   *
   * @return  The number of updates that have been replayed in this replica
   *          after automatically resolving a modify conflict, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesReplayedAfterModifyConflict()
  {
    return replayedAfterModifyConflict;
  }



  /**
   * Retrieves the number of updates that have been replayed in this replica
   * after automatically resolving a naming conflict.
   *
   * @return  The number of updates that have been replayed in this replica
   *          after automatically resolving a naming conflict, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUpdatesReplayedAfterNamingConflict()
  {
    return replayedAfterNamingConflict;
  }



  /**
   * Retrieves the number of updates that could not be replayed as a result of a
   * naming conflict that could not be automatically resolved.
   *
   * @return  The number of updates that could not be replayed as a result of a
   *          naming conflict that could not be automatically resolved, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getUnresolvedNamingConflicts()
  {
    return unresolvedNamingConflicts;
  }



  /**
   * Retrieves the current receive window size for this replica.
   *
   * @return  The current receive window size for this replica, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentReceiveWindowSize()
  {
    return currentReceiveWindowSize;
  }



  /**
   * Retrieves the current send window size for this replica.
   *
   * @return  The current send window size for this replica, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Long getCurrentSendWindowSize()
  {
    return currentSendWindowSize;
  }



  /**
   * Retrieves the maximum receive window size for this replica.
   *
   * @return  The maximum receive window size for this replica, or {@code null}
   *          if it was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaximumReceiveWindowSize()
  {
    return maxReceiveWindowSize;
  }



  /**
   * Retrieves the maximum send window size for this replica.
   *
   * @return  The maximum send window size for this replica, or {@code null} if
   *          it was not included in the monitor entry.
   */
  @Nullable()
  public Long getMaximumSendWindowSize()
  {
    return maxSendWindowSize;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_REPLICA_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_REPLICA_MONITOR_DESC.get();
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

    if (baseDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_REPLICA_DISPNAME_BASE_DN.get(),
           INFO_REPLICA_DESC_BASE_DN.get(),
           baseDN);
    }

    if (replicaID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICA_ID,
           INFO_REPLICA_DISPNAME_REPLICA_ID.get(),
           INFO_REPLICA_DESC_REPLICA_ID.get(),
           replicaID);
    }

    if (generationID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_GENERATION_ID,
           INFO_REPLICA_DISPNAME_GENERATION_ID.get(),
           INFO_REPLICA_DESC_GENERATION_ID.get(),
           generationID);
    }

    if (replicationServerAddress != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTED_TO,
           INFO_REPLICA_DISPNAME_CONNECTED_TO.get(),
           INFO_REPLICA_DESC_CONNECTED_TO.get(),
           replicationServerAddress + ':' + replicationServerPort);
    }

    if (useSSL != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SSL_ENCRYPTION,
           INFO_REPLICA_DISPNAME_USE_SSL.get(),
           INFO_REPLICA_DESC_USE_SSL.get(),
           useSSL);
    }

    if (lostConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LOST_CONNECTIONS,
           INFO_REPLICA_DISPNAME_LOST_CONNECTIONS.get(),
           INFO_REPLICA_DESC_LOST_CONNECTIONS.get(),
           lostConnections);
    }

    if (receivedUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RECEIVED_UPDATES,
           INFO_REPLICA_DISPNAME_RECEIVED_UPDATES.get(),
           INFO_REPLICA_DESC_RECEIVED_UPDATES.get(),
           receivedUpdates);
    }

    if (sentUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SENT_UPDATES,
           INFO_REPLICA_DISPNAME_SENT_UPDATES.get(),
           INFO_REPLICA_DESC_SENT_UPDATES.get(),
           sentUpdates);
    }

    if (pendingUpdates != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PENDING_UPDATES,
           INFO_REPLICA_DISPNAME_PENDING_UPDATES.get(),
           INFO_REPLICA_DESC_PENDING_UPDATES.get(),
           pendingUpdates);
    }

    if (totalReplayed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_TOTAL_REPLAYED,
           INFO_REPLICA_DISPNAME_TOTAL_REPLAYED.get(),
           INFO_REPLICA_DESC_TOTAL_REPLAYED.get(),
           totalReplayed);
    }

    if (successfullyReplayed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SUCCESSFUL_REPLAYED,
           INFO_REPLICA_DISPNAME_SUCCESSFUL_REPLAYED.get(),
           INFO_REPLICA_DESC_SUCCESSFUL_REPLAYED.get(),
           successfullyReplayed);
    }

    if (replayedAfterModifyConflict != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RESOLVED_MODIFY_CONFLICTS,
           INFO_REPLICA_DISPNAME_RESOLVED_MODIFY_CONFLICTS.get(),
           INFO_REPLICA_DESC_RESOLVED_MODIFY_CONFLICTS.get(),
           replayedAfterModifyConflict);
    }

    if (replayedAfterNamingConflict != null)
    {
      addMonitorAttribute(attrs,
           ATTR_RESOLVED_NAMING_CONFLICTS,
           INFO_REPLICA_DISPNAME_RESOLVED_NAMING_CONFLICTS.get(),
           INFO_REPLICA_DESC_RESOLVED_NAMING_CONFLICTS.get(),
           replayedAfterNamingConflict);
    }

    if (unresolvedNamingConflicts != null)
    {
      addMonitorAttribute(attrs,
           ATTR_UNRESOLVED_NAMING_CONFLICTS,
           INFO_REPLICA_DISPNAME_UNRESOLVED_NAMING_CONFLICTS.get(),
           INFO_REPLICA_DESC_UNRESOLVED_NAMING_CONFLICTS.get(),
           unresolvedNamingConflicts);
    }

    if (currentReceiveWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_RECEIVE_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_CURRENT_RECEIVE_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_CURRENT_RECEIVE_WINDOW_SIZE.get(),
           currentReceiveWindowSize);
    }

    if (currentSendWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CURRENT_SEND_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_CURRENT_SEND_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_CURRENT_SEND_WINDOW_SIZE.get(),
           currentSendWindowSize);
    }

    if (maxReceiveWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_RECEIVE_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_MAX_RECEIVE_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_MAX_RECEIVE_WINDOW_SIZE.get(),
           maxReceiveWindowSize);
    }

    if (maxSendWindowSize != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MAX_SEND_WINDOW_SIZE,
           INFO_REPLICA_DISPNAME_MAX_SEND_WINDOW_SIZE.get(),
           INFO_REPLICA_DESC_MAX_SEND_WINDOW_SIZE.get(),
           maxSendWindowSize);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
