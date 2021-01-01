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
import java.text.SimpleDateFormat;
import java.util.Date;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that contains information about a
 * replication server contained in a replication summary monitor entry.
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
public final class ReplicationSummaryReplicationServer
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3021672478708746554L;



  // The date of the last successful connection to this replication server.
  @Nullable private final Date replicationServerLastConnected;

  // The date of the last failed connection to this replication server.
  @Nullable private final Date replicationServerLastFailed;

  // The number of times connection attempts to this replication server have
  // failed. The counter is reset after a successful connection.
  @Nullable private final Long replicationServerFailedAttempts;

  // The port number for this replication server.
  @Nullable private final Long replicationServerPort;

  // The generation ID for this replication server.
  @Nullable private final String generationID;

  // The address for this replication server.
  @Nullable private final String replicationServerAddress;

  // The replication server ID for this replication server.
  @Nullable private final String replicationServerID;

  // The status for this replication server.
  @Nullable private final String replicationServerStatus;

  // The value used to create this replication summary replica object.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new replication summary replication server object from the
   * provided string representation.
   *
   * @param  value  The value string to be parsed as a replication summary
   *                replication server object.
   */
  public ReplicationSummaryReplicationServer(@NotNull final String value)
  {
    stringRepresentation = value;

    generationID        = getElementValue(value, "generation-id");
    replicationServerID = getElementValue(value, "server-id");

    final String hostPort = getElementValue(value, "server");
    if (hostPort == null)
    {
      replicationServerAddress = null;
      replicationServerPort    = null;
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

      replicationServerAddress = a;
      replicationServerPort    = p;
    }

    replicationServerStatus = getElementValue(value, "status");
    replicationServerLastConnected  =
         getElementDateValue(value, "last-connected");
    replicationServerLastFailed = getElementDateValue(value, "last-failed");
    replicationServerFailedAttempts =
         getElementLongValue(value, "failed-attempts");
  }



  /**
   * Retrieves the value for the specified element in the replica string.
   *
   * @param  s  The string to be parsed.
   * @param  n  The name of the element for which to retrieve the value.
   *
   * @return  The value for the specified element in the replica string, or
   *          {@code null} if it was not present or could not be determined.
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
   * Retrieves the value for the specified element in the replica string as a
   * {@code Date} object.
   *
   * @param  s  The string to be parsed.
   * @param  n  The name of the element for which to retrieve the value.
   *
   * @return  The value for the specified element in the replica string as a
   *          {@code Date}, or {@code null} if it was not present or could not
   *          be determined or parsed as a {@code Date}.
   */
  @Nullable()
  private static Date getElementDateValue(@NotNull final String s,
                                          @NotNull final String n)
  {
    final String stringValue = getElementValue(s, n);
    if (stringValue == null)
    {
      return null;
    }

    try
    {
      final SimpleDateFormat f =
           new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");
      return f.parse(stringValue);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value for the specified element in the replica string as a
   * {@code Long} object.
   *
   * @param  s  The string to be parsed.
   * @param  n  The name of the element for which to retrieve the value.
   *
   * @return  The value for the specified element in the replica string as a
   *          {@code Long}, or {@code null} if it was not present or could not
   *          be determined or parsed as a {@code Long}.
   */
  @Nullable()
  private static Long getElementLongValue(@NotNull final String s,
                                          @NotNull final String n)
  {
    final String stringValue = getElementValue(s, n);
    if (stringValue == null)
    {
      return null;
    }

    try
    {
      return Long.valueOf(stringValue);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the replication server ID for this replication server.
   *
   * @return  The replication server ID for this replication server, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public String getReplicationServerID()
  {
    return replicationServerID;
  }



  /**
   * Retrieves the address used to communicate with this replication server.
   *
   * @return  The address used to communicate with this replication server, or
   *          {@code null} if that information is not available.
   */
  @Nullable()
  public String getReplicationServerAddress()
  {
    return replicationServerAddress;
  }



  /**
   * Retrieves the port number used to communicate with this replication server.
   *
   * @return  The port number used to communicate with this replication server,
   *          or {@code null} if that information is not available.
   */
  @Nullable()
  public Long getReplicationServerPort()
  {
    return replicationServerPort;
  }



  /**
   * Retrieves the generation ID for this replication server.
   *
   * @return  The generation ID for this replication server, or {@code null} if
   *          that information is not available.
   */
  @Nullable()
  public String getGenerationID()
  {
    return generationID;
  }



  /**
   * Retrieves the status for this replication server.
   *
   * @return  The status for this replication server, or {@code null} if
   *          that information is not available.
   */
  @Nullable()
  public String getReplicationServerStatus()
  {
    return replicationServerStatus;
  }



  /**
   * Retrieves the date of the last successful connection to this replication
   * server.
   *
   * @return  The the date of the last successful connection to this replication
   *          server, or {@code null} if that information is not available.
   */
  @Nullable()
  public Date getReplicationServerLastConnected()
  {
    return replicationServerLastConnected;
  }



  /**
   * Retrieves the date of the last failed connection to this replication
   * server.
   *
   * @return  The the date of the last failed connection to this replication
   *          server, or {@code null} if that information is not available.
   */
  @Nullable()
  public Date getReplicationServerLastFailed()
  {
    return replicationServerLastFailed;
  }



  /**
   * Retrieves the number of failed connection attempts since the last
   * successful connection to this replication server.
   *
   * @return  The number of failed connection attempts since the last successful
   *          connection to this replication server, or {@code null} if that
   *          information is not available.
   */
  @Nullable()
  public Long getReplicationServerFailedAttempts()
  {
    return replicationServerFailedAttempts;
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
