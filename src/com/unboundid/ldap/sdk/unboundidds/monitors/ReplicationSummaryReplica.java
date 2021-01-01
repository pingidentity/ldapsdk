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



import java.io.Serializable;
import java.util.Date;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that contains information about a
 * replica contained in a replication summary monitor entry.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplicationSummaryReplica
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5967001261856109688L;



  // The date of the oldest backlog change.
  @Nullable private final Date oldestBacklogChangeDate;

  // The LDAP server port for this replica.
  @Nullable private final Long ldapServerPort;

  // The replication backlog, presented as the number of missing changes in the
  // replica.
  @Nullable private final Long replicationBacklog;

  // The peak update rate in operations per second.
  @Nullable private final Long peakUpdateRate;

  // The recent update rate in operations per second.
  @Nullable private final Long recentUpdateRate;

  // The generation ID for the data in the replica.
  @Nullable private final String generationID;

  // The LDAP server address for this replica.
  @Nullable private final String ldapServerAddress;

  // The replica ID for this replica.
  @Nullable private final String replicaID;

  // The replication server ID for the replication server to which this replica
  // is connected.
  @Nullable private final String replicationServerID;

  // The value used to create this replication summary replica object.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new replication summary replica object from the provided string
   * representation.
   *
   * @param  value  The value string to be parsed as a replication summary
   *                replica object.
   */
  public ReplicationSummaryReplica(@NotNull final String value)
  {
    stringRepresentation = value;

    replicaID           = getElementValue(value, "replica-id");
    replicationServerID = getElementValue(value, "connected-to");
    generationID        = getElementValue(value, "generation-id");

    final String hostPort = getElementValue(value, "ldap-server");
    if (hostPort == null)
    {
      ldapServerAddress = null;
      ldapServerPort    = null;
    }
    else
    {
      Long p;
      String a;

      try
      {
        final int colonPos = hostPort.indexOf(':');
        a = hostPort.substring(0, colonPos);
        p = Long.parseLong(hostPort.substring(colonPos+1));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        a = null;
        p = null;
      }

      ldapServerAddress = a;
      ldapServerPort    = p;
    }

    String replicationBacklogStr =
            getElementValue(value, "replication-backlog");
    if (replicationBacklogStr == null)
    {
      // missing-changes was renamed to replication-backlog, so we check
      // for missing-changes to maintain backwards compatibility.
      replicationBacklogStr = getElementValue(value, "missing-changes");
    }

    if (replicationBacklogStr == null)
    {
      replicationBacklog = null;
    }
    else
    {
      Long mc;

      try
      {
        mc = Long.parseLong(replicationBacklogStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        mc = null;
      }

      replicationBacklog = mc;
    }

    String rateStr = getElementValue(value, "recent-update-rate");
    if (rateStr == null)
    {
      recentUpdateRate = null;
    }
    else
    {
      Long r;
      try
      {
        final int slashPos = rateStr.indexOf('/');
        r = Long.parseLong(rateStr.substring(0, slashPos));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        r = null;
      }
      recentUpdateRate = r;
    }

    rateStr = getElementValue(value, "peak-update-rate");
    if (rateStr == null)
    {
      peakUpdateRate = null;
    }
    else
    {
      Long r;
      try
      {
        final int slashPos = rateStr.indexOf('/');
        r = Long.parseLong(rateStr.substring(0, slashPos));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        r = null;
      }
      peakUpdateRate = r;
    }

    String dateStr =
         getElementValue(value, "age-of-oldest-backlog-change");
    if (dateStr == null)
    {
      // age-of-oldest-missing-change was renamed to
      // age-of-oldest-backlog-change, so we check
      // for age-of-oldest-missing-change to maintain backwards compatibility.
      dateStr = getElementValue(value, "age-of-oldest-missing-change");
    }

    if (dateStr == null)
    {
      oldestBacklogChangeDate = null;
    }
    else
    {
      Date d;

      try
      {
        final int spacePos = dateStr.indexOf(' ');
        d = StaticUtils.decodeGeneralizedTime(dateStr.substring(0, spacePos));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        d = null;
      }

      oldestBacklogChangeDate = d;
    }
  }



  /**
   * Retrieves the value for the specified element in the replica string.
   *
   * @param  s  The string to be parsed.
   * @param  n  The name of the element for which to retrieve the value.
   *
   * @return  The value for the specified element in the replica string, or
   *          {@code null} if it was not present, could not be determined, or
   *          was an empty string.
   */
  @Nullable()
  private static String getElementValue(@NotNull final String s,
                                        @NotNull final String n)
  {
    final String nPlusEQ = n + "=\"";

    int pos = s.indexOf(nPlusEQ);
    if (pos < 0)
    {
      return null;
    }
    pos += nPlusEQ.length();

    final int closePos = s.indexOf('"', pos);
    if (closePos <= pos)
    {
      return null;
    }

    return s.substring(pos, closePos);
  }



  /**
   * Retrieves the replica ID for this replica.
   *
   * @return  The replica ID for this replica, or {@code null} if that
   *          information is not available.
   */
  @Nullable()
  public String getReplicaID()
  {
    return replicaID;
  }



  /**
   * Retrieves the address used to communicate with this replica via LDAP.
   *
   * @return  The address used to communicate with this replica via LDAP, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public String getLDAPServerAddress()
  {
    return ldapServerAddress;
  }



  /**
   * Retrieves the port number used to communicate with this replica via LDAP.
   *
   * @return  The port number used to communicate with this replica via LDAP, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public Long getLDAPServerPort()
  {
    return ldapServerPort;
  }



  /**
   * Retrieves the replication server ID for the replication server to which
   * this replica is connected.
   *
   * @return  The replication server ID for the replication server to which this
   *          replica is connected, or {@code null} if that information is not
   *          available.
   */
  @Nullable()
  public String getReplicationServerID()
  {
    return replicationServerID;
  }



  /**
   * Retrieves the generation ID for this replica.
   *
   * @return  The generation ID for this replica, or {@code null} if that
   *          information is not available.
   */
  @Nullable()
  public String getGenerationID()
  {
    return generationID;
  }



  /**
   * Retrieves the recent update rate for this replica in operations per second.
   *
   * @return  The recent update rate for this replica in operations per second,
   *          or {@code null} if that information is not available.
   */
  @Nullable()
  public Long getRecentUpdateRate()
  {
    return recentUpdateRate;
  }



  /**
   * Retrieves the peak update rate for this replica in operations per second.
   *
   * @return  The peak update rate for this replica in operations per second, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public Long getPeakUpdateRate()
  {
    return peakUpdateRate;
  }



  /**
   * Retrieves the replication backlog, represented as the number of missing
   * changes, for this replica.
   *
   * @return  The replication backlog, represented as the number of missing
   *          changes, for this replica , or {@code null} if
   *          that information is not available.
   *
   * @deprecated  Use {@link #getReplicationBacklog()} instead.
   */
  @Deprecated
  @Nullable()
  public Long getMissingChanges()
  {
    return getReplicationBacklog();
  }



  /**
   * Retrieves the replication backlog, represented as the number of missing
   * changes, for this replica.
   *
   * @return  The replication backlog, represented as the number of missing
   *          changes, for this replica , or {@code null} if
   *          that information is not available.
   */
  @Nullable()
  public Long getReplicationBacklog()
  {
    return replicationBacklog;
  }



  /**
   * Retrieves the date of the oldest backlog change for this replica.
   *
   * @return  The date of the oldest backlog change for this replica, or
   *          {@code null} if that information is not available or there are no
   *          backlog changes.
   *
   * @deprecated  Use {@link #getOldestBacklogChangeDate()} instead.
   */
  @Deprecated
  @Nullable()
  public Date getOldestMissingChangeDate()
  {
    return getOldestBacklogChangeDate();
  }



  /**
   * Retrieves the date of the oldest backlog change for this replica.
   *
   * @return  The date of the oldest backlog change for this replica, or
   *          {@code null} if that information is not available or there are no
   *          backlog changes.
   */
  @Nullable()
  public Date getOldestBacklogChangeDate()
  {
    return oldestBacklogChangeDate;
  }



  /**
   * Retrieves a string representation of this replication summary replica.
   *
   * @return  A string representation of this replication summary replica.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }
}
