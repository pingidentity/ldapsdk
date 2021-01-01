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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.DN;
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
 * of a replication server, including the base DNs for replicated content, the
 * generation ID for each of those base DNs, the replication server ID, and the
 * port number on which the replication server is listening.
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
 * The server should present at most one replication server monitor entry.  It
 * can be retrieved using the
 * {@link MonitorManager#getReplicationServerMonitorEntry} method.  This entry
 * provides specific methods for accessing information about the replication
 * server.  Alternately, this information may be accessed using the generic API.
 * See the {@link MonitorManager} class documentation for an example that
 * demonstrates the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicationServerMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in replication server monitor entries.
   */
  @NotNull static final String REPLICATION_SERVER_MONITOR_OC =
       "ds-replication-server-monitor-entry";



  /**
   * The name of the attribute that contains the base DNs for the replicated
   * data.
   */
  @NotNull private static final String ATTR_BASE_DN = "base-dn";



  /**
   * The name of the attribute that contains the generation IDs that correspond
   * to the replicated base DNs.
   */
  @NotNull private static final String ATTR_BASE_DN_GENERATION_ID =
       "base-dn-generation-id";



  /**
   * The name of the attribute that contains the server ID for the replication
   * server.
   */
  @NotNull private static final String ATTR_REPLICATION_SERVER_ID =
       "replication-server-id";



  /**
   * The name of the attribute that contains the port number on which the
   * replication server listens for communication from other servers.
   */
  @NotNull private static final String ATTR_REPLICATION_SERVER_PORT =
       "replication-server-port";



  /**
   * The name of the attribute that indicates whether SSL encryption is
   * available for use.
   */
  @NotNull private static final String ATTR_SSL_AVAILABLE =
       "ssl-encryption-available";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7488640967498574690L;



  // Indicates whether SSL encryption is available.
  @Nullable private final Boolean sslEncryptionAvailable;

  // The base DNs for the replicated data.
  @NotNull private final List<String> baseDNs;

  // The port number on which the replication server listens for communication
  // from other servers.
  @Nullable private final Long replicationServerPort;

  // A map of the generation IDs for each of the replicated base DNs.
  @NotNull private final Map<DN,String> generationIDs;

  // The replication server ID for the replication server.
  @Nullable private final String replicationServerID;



  /**
   * Creates a new replication server monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a replication server monitor
   *                entry.  It must not be {@code null}.
   */
  public ReplicationServerMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    baseDNs                = getStrings(ATTR_BASE_DN);
    replicationServerID    = getString(ATTR_REPLICATION_SERVER_ID);
    replicationServerPort  = getLong(ATTR_REPLICATION_SERVER_PORT);
    sslEncryptionAvailable = getBoolean(ATTR_SSL_AVAILABLE);

    final List<String> baseDNsAndIDs = getStrings(ATTR_BASE_DN_GENERATION_ID);
    final Map<DN,String> idMap = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(baseDNsAndIDs.size()));
    for (final String s : baseDNsAndIDs)
    {
      try
      {
        final int lastSpacePos = s.lastIndexOf(' ');
        final DN dn = new DN(s.substring(0, lastSpacePos));
        idMap.put(dn, s.substring(lastSpacePos+1));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
    generationIDs = Collections.unmodifiableMap(idMap);
  }



  /**
   * Retrieves the base DNs for replicated content managed by this replication
   * server.
   *
   * @return  The base DNs for replicated content managed by this replication
   *          server, or an empty list if it was not included in the monitor
   *          entry.
   */
  @NotNull()
  public List<String> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * Retrieves a map of generation IDs for the available base DNs.
   *
   * @return  A map of generation IDs for the available base DNs, or an empty
   *          map if it was not included in the monitor entry.
   */
  @NotNull()
  public Map<DN,String> getGenerationIDs()
  {
    return generationIDs;
  }



  /**
   * Retrieves the generation ID for the specified base DN.
   *
   * @param  baseDN  The base DN for which to retrieve the generation ID.
   *
   * @return  The generation ID for the specified base DN, or {@code null} if
   *          there no generation ID is available for the provided base DN, or
   *          the provided base DN is not a valid DN.
   */
  @Nullable()
  public String getGenerationID(@NotNull final String baseDN)
  {
    try
    {
      return getGenerationID(new DN(baseDN));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the generation ID for the specified base DN.
   *
   * @param  baseDN  The base DN for which to retrieve the generation ID.
   *
   * @return  The generation ID for the specified base DN, or {@code null} if
   *          there no generation ID is available for the provided base DN.
   */
  @Nullable()
  public String getGenerationID(@NotNull final DN baseDN)
  {
    return generationIDs.get(baseDN);
  }



  /**
   * Retrieves the server ID for the replication server.
   *
   * @return  The server ID for the replication server, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public String getReplicationServerID()
  {
    return replicationServerID;
  }



  /**
   * Retrieves the port number for the replication server.
   *
   * @return  The port number for the replication server, or {@code null} if it
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Long getReplicationServerPort()
  {
    return replicationServerPort;
  }



  /**
   * Indicates whether the replication server provides support for SSL
   * encryption.
   *
   * @return  {@code true} if the replication server supports SSL encryption,
   *          {@code false} if it does not, or {@code null} if that information
   *          was not included in the monitor entry.
   */
  @Nullable()
  public Boolean sslEncryptionAvailable()
  {
    return sslEncryptionAvailable;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_REPLICATION_SERVER_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_REPLICATION_SERVER_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));

    if (! baseDNs.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_BASE_DN,
           INFO_REPLICATION_SERVER_DISPNAME_BASE_DN.get(),
           INFO_REPLICATION_SERVER_DESC_BASE_DN.get(),
           baseDNs);
    }

    if (! generationIDs.isEmpty())
    {
      final ArrayList<String> idStrings =
           new ArrayList<>(generationIDs.size());
      for (final Map.Entry<DN,String> e : generationIDs.entrySet())
      {
        idStrings.add(e.getKey().toNormalizedString() + ' ' + e.getValue());
      }

      addMonitorAttribute(attrs,
           ATTR_BASE_DN_GENERATION_ID,
           INFO_REPLICATION_SERVER_DISPNAME_BASE_DN_GENERATION_ID.get(),
           INFO_REPLICATION_SERVER_DESC_BASE_DN_GENERATION_ID.get(),
           idStrings);
    }

    if (replicationServerID != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_SERVER_ID,
           INFO_REPLICATION_SERVER_DISPNAME_REPLICATION_SERVER_ID.get(),
           INFO_REPLICATION_SERVER_DESC_REPLICATION_SERVER_ID.get(),
           replicationServerID);
    }

    if (replicationServerPort != null)
    {
      addMonitorAttribute(attrs,
           ATTR_REPLICATION_SERVER_PORT,
           INFO_REPLICATION_SERVER_DISPNAME_REPLICATION_SERVER_PORT.get(),
           INFO_REPLICATION_SERVER_DESC_REPLICATION_SERVER_PORT.get(),
           replicationServerPort);
    }

    if (sslEncryptionAvailable != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SSL_AVAILABLE,
           INFO_REPLICATION_SERVER_DISPNAME_SSL_AVAILABLE.get(),
           INFO_REPLICATION_SERVER_DESC_SSL_AVAILABLE.get(),
           sslEncryptionAvailable);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
