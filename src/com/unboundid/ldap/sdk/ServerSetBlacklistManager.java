/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a mechanism for maintaining a blacklist of servers that
 * have recently been found to be unacceptable for use by a server set.  Server
 * sets that use this class can temporarily avoid trying to access servers that
 * may be experiencing problems.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ServerSetBlacklistManager
{
  // A reference to a timer that is used to periodically check the status of
  // blacklisted servers.
  @NotNull private final AtomicReference<Timer> timerReference;

  // The bind request to use to authenticate newly created connections.
  @Nullable private final BindRequest bindRequest;

  // The connection options to use when creating connections.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // The length of time, in milliseconds, between checks to determine whether
  // a server should be removed from the blacklist.
  private final long checkIntervalMillis;

  // A map of currently blacklisted servers.
  @NotNull private final Map<ObjectPair<String,Integer>,
       LDAPConnectionPoolHealthCheck> blacklistedServers;

  // The post-connect processor to use for newly created connections.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The socket factory to use when creating connections.
  @NotNull private final SocketFactory socketFactory;

  // A string representation of the associated server set.
  @NotNull private final String serverSetString;



  /**
   * Creates a new server set blacklist manager with the provided information.
   *
   * @param  serverSet             The server set with which this blacklist
   *                               manager is associated.
   * @param  socketFactory         An optional socket factory to use when
   *                               creating connections.  If this is
   *                               {@code null}, a default socket factory will
   *                               be used.
   * @param  connectionOptions     An optional set of connection options to use
   *                               when creating connections.  If this is
   *                               {@code null}, a default set of connection
   *                               options will be used.
   * @param  bindRequest           An optional bind request to use to
   *                               authenticate connections that are
   *                               established.  It may be {@code null} if no
   *                               authentication should be performed.
   * @param  postConnectProcessor  An optional post-connect processor that
   *                               should be invoked for any connection that is
   *                               established.  It may be {@code null} if no
   *                               post-connect processing should be performed.
   * @param  checkIntervalMillis   The length of time, in milliseconds, between
   *                               checks to determine whether a server should
   *                               be removed from the blacklist.
   */
  ServerSetBlacklistManager(@NotNull final ServerSet serverSet,
       @Nullable final SocketFactory socketFactory,
       @Nullable final LDAPConnectionOptions connectionOptions,
       @Nullable final BindRequest bindRequest,
       @Nullable final PostConnectProcessor postConnectProcessor,
       final long checkIntervalMillis)
  {
    Validator.ensureTrue((checkIntervalMillis > 0L),
         "ServerSetBlacklistManager.checkIntervalMillis must be greater " +
              "than zero.");
    this.checkIntervalMillis = checkIntervalMillis;

    serverSetString = serverSet.toString();

    if (socketFactory == null)
    {
      this.socketFactory = SocketFactory.getDefault();
    }
    else
    {
      this.socketFactory = socketFactory;
    }

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions;
    }

    this.bindRequest = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    blacklistedServers =
         new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(10));
    timerReference = new AtomicReference<>();
  }



  /**
   * Indicates whether the blacklist is currently empty.
   *
   * @return  {@code true} if the blacklist is currently empty, or {@code false}
   *          if it contains at least one server.
   */
  public boolean isEmpty()
  {
    if (blacklistedServers.isEmpty())
    {
      return true;
    }
    else
    {
      ensureTimerIsRunning();
      return false;
    }
  }



  /**
   * Retrieves the number of servers currently on the blacklist.
   *
   * @return  The number of servers currently on the blacklist.
   */
  public int size()
  {
    if (blacklistedServers.isEmpty())
    {
      return 0;
    }
    else
    {
      ensureTimerIsRunning();
      return blacklistedServers.size();
    }
  }



  /**
   * Retrieves a list of the servers currently on the blacklist.
   *
   * @return  A list of the servers currently on the blacklist.
   */
  @NotNull()
  public Set<ObjectPair<String,Integer>> getBlacklistedServers()
  {
    if (! blacklistedServers.isEmpty())
    {
      ensureTimerIsRunning();
    }

    return Collections.unmodifiableSet(
         new HashSet<>(blacklistedServers.keySet()));
  }



  /**
   * Indicates whether the specified server is currently on the blacklist.
   *
   * @param  host  The address of the server for which to make the
   *               determination.  It must not be {@code null}.
   * @param  port  The port of the server for which to make the determination.
   *               It must be between 1 and 65535, inclusive.
   *
   * @return  {@code true} if the server is on the blacklist, or {@code false}
   *          if not.
   */
  public boolean isBlacklisted(@NotNull final String host, final int port)
  {
    if (blacklistedServers.isEmpty())
    {
      return false;
    }
    else
    {
      ensureTimerIsRunning();
      return blacklistedServers.containsKey(new ObjectPair<>(host, port));
    }
  }



  /**
   * Indicates whether the specified server is currently on the blacklist.
   *
   * @param  hostPort  An {@code ObjectPair} containing the address and port of
   *                   the server for which to make the determination.  It must
   *                   not be {@code null}.
   *
   * @return  {@code true} if the server is on the blacklist, or {@code false}
   *          if not.
   */
  public boolean isBlacklisted(
                      @NotNull final ObjectPair<String,Integer> hostPort)
  {
    if (blacklistedServers.isEmpty())
    {
      return false;
    }
    else
    {
      ensureTimerIsRunning();
      return blacklistedServers.containsKey(hostPort);
    }
  }



  /**
   * Adds the specified server to the blacklist.
   *
   * @param  host         The address of the server to be added.  It must not be
   *                      {@code null}.
   * @param  port         The port of the server to be added.  It must be
   *                      between 1 and 65535, inclusive.
   * @param  healthCheck  The health check to use for periodic checks to see if
   *                      the server can be removed from the blacklist.  It may
   *                      be {@code null} if no health checking is required.
   */
  void addToBlacklist(@NotNull final String host, final int port,
                      @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
  {
    addToBlacklist(new ObjectPair<>(host, port), healthCheck);
  }



  /**
   * Adds the specified server to the blacklist.
   *
   * @param  hostPort     An {@code ObjectPair} containing the address and port
   *                      of the server to be added.  It must not be
   *                      {@code null}.
   * @param  healthCheck  The health check to use for periodic checks to see if
   *                      the server can be removed from the blacklist.  It may
   *                      be {@code null} if no health checking is required.
   */
  void addToBlacklist(@NotNull final ObjectPair<String,Integer> hostPort,
                      @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
  {
    if (healthCheck == null)
    {
      blacklistedServers.put(hostPort, new LDAPConnectionPoolHealthCheck());
    }
    else
    {
      blacklistedServers.put(hostPort, healthCheck);
    }
    ensureTimerIsRunning();
  }



  /**
   * Removes the specified server from the blacklist.
   *
   * @param  host  The address of the server to be removed.  It must not be
   *               {@code null}.
   * @param  port  The port of the server to be removed.  It must be between 1
   *               and 65535, inclusive.
   */
  void removeFromBlacklist(@NotNull final String host, final int port)
  {
    removeFromBlacklist(new ObjectPair<>(host, port));
  }



  /**
   * Removes the specified server from the blacklist.
   *
   * @param  hostPort  An {@code ObjectPair} containing the address and port of
   *                   the server to be removed.  It must not be {@code null}.
   */
  void removeFromBlacklist(@NotNull final ObjectPair<String,Integer> hostPort)
  {
    blacklistedServers.remove(hostPort);
    if (! blacklistedServers.isEmpty())
    {
      ensureTimerIsRunning();
    }
  }



  /**
   * Clears the blacklist.
   */
  void clear()
  {
    blacklistedServers.clear();
  }



  /**
   * Ensures that there is a timer to periodically check the status of
   * blacklisted servers.
   */
  private synchronized void ensureTimerIsRunning()
  {
    Timer timer = timerReference.get();
    if (timer == null)
    {
      timer = new Timer(
           "ServerSet Blacklist Manager Timer for " + serverSetString, true);
      timerReference.set(timer);

      timer.scheduleAtFixedRate(new ServerSetBlacklistManagerTimerTask(this),
           checkIntervalMillis, checkIntervalMillis);
    }
  }



  /**
   * Checks all blacklisted servers to see if any of them should be removed from
   * the blacklist.  If there are no servers on the blacklist and the timer is
   * running, then it will be shut down.
   */
  void checkBlacklistedServers()
  {
    // Iterate through the blacklist and check each of the servers.  If we find
    // one that is acceptable, then remove it from the blacklist.
    final Iterator<Map.Entry<ObjectPair<String,Integer>,
         LDAPConnectionPoolHealthCheck>> iterator =
         blacklistedServers.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<ObjectPair<String,Integer>,
           LDAPConnectionPoolHealthCheck> e = iterator.next();
      final ObjectPair<String,Integer> hostPort = e.getKey();
      final LDAPConnectionPoolHealthCheck healthCheck = e.getValue();
      try (LDAPConnection conn = new LDAPConnection(socketFactory,
                connectionOptions, hostPort.getFirst(), hostPort.getSecond()))
      {
        ServerSet.doBindPostConnectAndHealthCheckProcessing(conn, bindRequest,
             postConnectProcessor, healthCheck);
        iterator.remove();
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }


    // If the blacklist is empty, then cancel the timer, if there is one.
    if (blacklistedServers.isEmpty())
    {
      synchronized (this)
      {
        if (blacklistedServers.isEmpty())
        {
          final Timer timer = timerReference.getAndSet(null);
          if (timer != null)
          {
            timer.cancel();
            timer.purge();
          }

          return;
        }
      }
    }
  }



  /**
   * Shuts down the blacklist manager.
   */
  public synchronized void shutDown()
  {
    final Timer timer = timerReference.getAndSet(null);
    if (timer != null)
    {
      timer.cancel();
      timer.purge();
    }

    blacklistedServers.clear();
  }



  /**
   * Retrieves a string representation of this server set blacklist manager.
   *
   * @return  A string representation of this server set blacklist manager.
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
   * Appends a string representation of this server set blacklist manager to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ServerSetBlacklistManager(serverSet='");
    buffer.append(serverSetString);
    buffer.append("', blacklistedServers={");

    final Iterator<ObjectPair<String,Integer>> iterator =
         blacklistedServers.keySet().iterator();
    while (iterator.hasNext())
    {
      final ObjectPair<String,Integer> hostPort = iterator.next();
      buffer.append('\'');
      buffer.append(hostPort.getFirst());
      buffer.append(':');
      buffer.append(hostPort.getSecond());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("}, checkIntervalMillis=");
    buffer.append(checkIntervalMillis);
    buffer.append(')');
  }
}
