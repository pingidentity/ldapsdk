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
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides general information about a
 * Directory Server connection handler.
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
 * Information that may be available in a connection handler monitor entry
 * includes:
 * <UL>
 *   <LI>The total number of connections that are established.</LI>
 *   <LI>The protocol that the connection handler uses to communicate with
 *       clients.</LI>
 *   <LI>A list of the listeners (addresses and ports on which the connection
 *       handler is listening for connections.</LI>
 *   <LI>Information about each of the connections established to the connection
 *       handler.  The information available for these connections may vary by
 *       connection handler type.</LI>
 * </UL>
 * The connection handler monitor entries provided by the server can be
 * retrieved using the {@link MonitorManager#getConnectionHandlerMonitorEntries}
 * method.  These entries provide specific methods for accessing information
 * about the connection handler (e.g., the
 * {@link ConnectionHandlerMonitorEntry#getNumConnections} method can be used
 * to retrieve the total number of connections established).  Alternately, this
 * information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ConnectionHandlerMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in connection handler monitor entries.
   */
  @NotNull static final String CONNECTION_HANDLER_MONITOR_OC =
       "ds-connectionhandler-monitor-entry";



  /**
   * The name of the attribute that contains information about the established
   * connections.
   */
  @NotNull private static final String ATTR_CONNECTION =
       "ds-connectionhandler-connection";



  /**
   * The name of the attribute that contains information about the listeners.
   */
  @NotNull private static final String ATTR_LISTENER =
       "ds-connectionhandler-listener";



  /**
   * The name of the attribute that contains information about the number of
   * established connections.
   */
  @NotNull private static final String ATTR_NUM_CONNECTIONS =
       "ds-connectionhandler-num-connections";



  /**
   * The name of the attribute that contains information about the protocol.
   */
  @NotNull private static final String ATTR_PROTOCOL =
       "ds-connectionhandler-protocol";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2922139631867367609L;



  // The list of connections currently established.
  @NotNull private final List<String> connections;

  // The list of listeners for the connection handler.
  @NotNull private final List<String> listeners;

  // The number of connections established.
  @Nullable private final Long numConnections;

  // The protocol used by the connection handler.
  @Nullable private final String protocol;



  /**
   * Creates a new connection handler monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a connection handler monitor
   *                entry.  It must not be {@code null}.
   */
  public ConnectionHandlerMonitorEntry(@NotNull final Entry entry)
  {
    super(entry);

    connections    = getStrings(ATTR_CONNECTION);
    listeners      = getStrings(ATTR_LISTENER);
    numConnections = getLong(ATTR_NUM_CONNECTIONS);
    protocol       = getString(ATTR_PROTOCOL);
  }



  /**
   * Retrieves a list of the string representations of the connections
   * established to the associated connection handler.  Values should be
   * space-delimited name-value pairs with the values surrounded by quotation
   * marks.
   *
   * @return  A list of the string representations of the connections
   *          established to the associated connection handler, or an empty list
   *          if it was not included in the monitor entry or there are no
   *          established connections.
   */
  @NotNull()
  public List<String> getConnections()
  {
    return connections;
  }



  /**
   * Retrieves a list of the listeners for the associated connection handler.
   *
   * @return  A list of the listeners for the associated connection handler, or
   *          an empty list if it was not included in the monitor entry or the
   *          connection handler does not have any listeners.
   */
  @NotNull()
  public List<String> getListeners()
  {
    return listeners;
  }



  /**
   * Retrieves the number of connections currently established to the associated
   * connection handler.
   *
   * @return  The number of connections currently established to the associated
   *          connection handler, or {@code null} if it was not included in the
   *          monitor entry.
   */
  @Nullable()
  public Long getNumConnections()
  {
    return numConnections;
  }



  /**
   * Retrieves the protocol for the associated connection handler.
   *
   * @return  The protocol for the associated connection handler, or
   *          {@code null} if it was not included in the monitor entry.
   */
  @Nullable()
  public String getProtocol()
  {
    return protocol;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDisplayName()
  {
    return INFO_CONNECTION_HANDLER_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getMonitorDescription()
  {
    return INFO_CONNECTION_HANDLER_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(4));

    if (protocol != null)
    {
      addMonitorAttribute(attrs,
           ATTR_PROTOCOL,
           INFO_CONNECTION_HANDLER_DISPNAME_PROTOCOL.get(),
           INFO_CONNECTION_HANDLER_DESC_PROTOCOL.get(),
           protocol);
    }

    if (! listeners.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_LISTENER,
           INFO_CONNECTION_HANDLER_DISPNAME_LISTENER.get(),
           INFO_CONNECTION_HANDLER_DESC_LISTENER.get(),
           listeners);
    }

    if (numConnections != null)
    {
      addMonitorAttribute(attrs,
           ATTR_NUM_CONNECTIONS,
           INFO_CONNECTION_HANDLER_DISPNAME_NUM_CONNECTIONS.get(),
           INFO_CONNECTION_HANDLER_DESC_NUM_CONNECTIONS.get(),
           numConnections);
    }

    if (! connections.isEmpty())
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTION,
           INFO_CONNECTION_HANDLER_DISPNAME_CONNECTION.get(),
           INFO_CONNECTION_HANDLER_DESC_CONNECTION.get(),
           connections);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
