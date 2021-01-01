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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides information about the health check states that may be
 * held by an LDAP external server.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum HealthCheckState
{
  /**
   * The health check state that indicates that the associated LDAP external
   * server is available.
   */
  AVAILABLE("available"),



  /**
   * The health check state that indicates that the associated LDAP external
   * server is in a degraded state.
   */
  DEGRADED("degraded"),



  /**
   * The health check state that indicates that the associated LDAP external
   * server is unavailable.
   */
  UNAVAILABLE("unavailable"),



  /**
   * The health check state that indicates that there are no local servers
   * defined, and therefore no health information is available for local
   * servers.
   */
  NO_LOCAL_SERVERS("no-local-servers"),



  /**
   * The health check state that indicates that there are no local servers
   * defined, and therefore no health information is available for remote
   * servers.
   */
  NO_REMOTE_SERVERS("no-remote-servers");



  // The name for this health check state.
  @NotNull private final String name;



  /**
   * Creates a new health check state with the specified name.
   *
   * @param  name  The name for this health check state.
   */
  HealthCheckState(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name for this health check state.
   *
   * @return  The name for this health check state.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the health check state with the specified name.
   *
   * @param  name  The name of the health check state to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The health check state with the specified name, or {@code null} if
   *          there is no health check state with the given name.
   */
  @Nullable()
  public static HealthCheckState forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "available":
        return AVAILABLE;
      case "degraded":
        return DEGRADED;
      case "unavailable":
        return UNAVAILABLE;
      case "nolocalservers":
      case "no-local-servers":
      case "no_local_servers":
        return NO_LOCAL_SERVERS;
      case "noremoteservers":
      case "no-remote-servers":
      case "no_remote_servers":
        return NO_REMOTE_SERVERS;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this health check state.
   *
   * @return  A string representation of this health check state.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
