/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides summary information about
 * a replicated data set within the Directory Server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The server will present a replication summary monitor entry for each base DN
 * for which replication is enabled, and it will include information about each
 * replica and replication server processing changes for that base DN.
 * Replication summary monitor entries can be retrieved using the
 * {@link MonitorManager#getReplicationSummaryMonitorEntries} method.  The
 * {@link #getBaseDN} method may be used to retrieve information about the
 * replicated base DN, the {@link #getReplicationServers} method may be used to
 * retrieve information about the replication servers for that base DN, and the
 * {@link #getReplicas} method may be used to retrieve information about the
 * replicas for that base DN.  Alternately, this information may be accessed
 * using the generic API.  See the {@link MonitorManager} class documentation
 * for an example that demonstrates the use of the generic API for accessing
 * monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicationSummaryMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in replication summary monitor entries.
   */
  static final String REPLICATION_SUMMARY_MONITOR_OC =
       "ds-replication-server-summary-monitor-entry";



  /**
   * The name of the attribute that contains the base DN for the replicated
   * data.
   */
  private static final String ATTR_BASE_DN = "base-dn";



  /**
   * The name of the attribute that contains information about the replication
   * servers for the replicated data.
   */
  private static final String ATTR_REPLICATION_SERVER = "replication-server";



  /**
   * The name of the attribute that contains information about the replicas
   * for the replicated data.
   */
  private static final String ATTR_REPLICA = "replica";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3144471025744197014L;



  // The base DN for the replicated data.
  private final String baseDN;

  // The list of replicas for the replicated data.
  private final List<ReplicationSummaryReplica> replicas;

  // The list of replication servers for the replicated data.
  private final List<ReplicationSummaryReplicationServer> replicationServers;



  /**
   * Creates a new replication summary monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a replication summary monitor
   *                entry.  It must not be {@code null}.
   */
  public ReplicationSummaryMonitorEntry(final Entry entry)
  {
    super(entry);

    baseDN = getString(ATTR_BASE_DN);

    final List<String> replicaStrings = getStrings(ATTR_REPLICA);
    final ArrayList<ReplicationSummaryReplica> replList =
         new ArrayList<ReplicationSummaryReplica>(replicaStrings.size());
    for (final String s : replicaStrings)
    {
      replList.add(new ReplicationSummaryReplica(s));
    }
    replicas = Collections.unmodifiableList(replList);

    final List<String> serverStrings = getStrings(ATTR_REPLICATION_SERVER);
    final ArrayList<ReplicationSummaryReplicationServer> serverList =
         new ArrayList<ReplicationSummaryReplicationServer>(
                  serverStrings.size());
    for (final String s : serverStrings)
    {
      serverList.add(new ReplicationSummaryReplicationServer(s));
    }
    replicationServers = Collections.unmodifiableList(serverList);
  }



  /**
   * Retrieves the base DN for this replication summary monitor entry.
   *
   * @return  The base DN for this replication summary monitor entry, or
   *          {@code null} if it was not included in the monitor entry.
   */
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves a list of information about the replicas described in this
   * replication server summary monitor entry.
   *
   * @return  A list of information about the replicas described in this
   *          replication server summary monitor entry, or an empty list if it
   *          was not included in the monitor entry.
   */
  public List<ReplicationSummaryReplica> getReplicas()
  {
    return replicas;
  }



  /**
   * Retrieves a list of information about the replication servers described in
   * this replication server summary monitor entry.
   *
   * @return  A list of information about the replication servers described in
   *          this replication server summary monitor entry, or an empty list if
   *          it was not included in the monitor entry.
   */
  public List<ReplicationSummaryReplicationServer> getReplicationServers()
  {
    return replicationServers;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_REPLICATION_SUMMARY_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_REPLICATION_SUMMARY_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>();

    if (baseDN != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_REPLICATION_SUMMARY_DISPNAME_BASE_DN.get(),
           INFO_REPLICATION_SUMMARY_DESC_BASE_DN.get(),
           baseDN);
    }

    if (! replicas.isEmpty())
    {
      final ArrayList<String> replStrings =
           new ArrayList<String>(replicas.size());
      for (final ReplicationSummaryReplica r : replicas)
      {
        replStrings.add(r.toString());
      }

      addMonitorAttribute(attrs,
           ATTR_REPLICA,
           INFO_REPLICATION_SUMMARY_DISPNAME_REPLICA.get(),
           INFO_REPLICATION_SUMMARY_DESC_REPLICA.get(),
           replStrings);
    }

    if (! replicationServers.isEmpty())
    {
      final ArrayList<String> serverStrings =
           new ArrayList<String>(replicationServers.size());
      for (final ReplicationSummaryReplicationServer s : replicationServers)
      {
        serverStrings.add(s.toString());
      }

      addMonitorAttribute(attrs,
           ATTR_REPLICATION_SERVER,
           INFO_REPLICATION_SUMMARY_DISPNAME_REPLICATION_SERVER.get(),
           INFO_REPLICATION_SUMMARY_DESC_REPLICATION_SERVER.get(),
           serverStrings);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
