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
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides general information about
 * the client connections currently established.  Note that the information
 * available for each client connection may vary based on the type of connection
 * handler with which that connection is associated.
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
 * The server should present at most one client connection monitor entry.  It
 * can be retrieved using the
 * {@link MonitorManager#getClientConnectionMonitorEntry} method.  The
 * {@link ClientConnectionMonitorEntry#getConnections} method may be used to
 * retrieve information for each connection.  Alternately, this information may
 * be accessed using the generic API.  See the {@link MonitorManager} class
 * documentation for an example that demonstrates the use of the generic API for
 * accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ClientConnectionMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in client connection monitor entries.
   */
  @NotNull static final String CLIENT_CONNECTION_MONITOR_OC =
       "ds-client-connection-monitor-entry";



  /**
   * The name of the attribute that contains information about the established
   * connections.
   */
  @NotNull private static final String ATTR_CONNECTION = "connection";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1705824766273147598L;



  // The list of connections currently established.
  @NotNull private final List<String> connections;



  /**
   * Creates a new client connection monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a client connection monitor entry.
   *                It must not be {@code null}.
   */
  public ClientConnectionMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    connections = getStrings(ATTR_CONNECTION);
  }



  /**
   * Retrieves a list of the string representations of the connections
   * established to the Directory Server.  Values should be space-delimited
   * name-value pairs with the values surrounded by quotation marks.
   *
   * @return  A list of the string representations of the connections
   *          established to the Directory Server, or an empty list if it was
   *          not included in the monitor entry or there are no established
   *          connections.
   */
  @NotNull()
  public List<String> getConnections()
  {
    return connections;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_CLIENT_CONNECTION_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_CLIENT_CONNECTION_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    if (! connections.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTION,
           INFO_CLIENT_CONNECTION_DISPNAME_CONNECTION.get(),
           INFO_CLIENT_CONNECTION_DESC_CONNECTION.get(),
           connections);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
