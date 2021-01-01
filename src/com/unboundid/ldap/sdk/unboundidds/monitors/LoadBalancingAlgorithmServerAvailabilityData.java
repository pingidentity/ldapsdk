/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a data structure that provides information about the
 * availability of an LDAP external server associated with a load-balancing
 * algorithm.
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
public final class LoadBalancingAlgorithmServerAvailabilityData
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2195372034654700615L;



  // The health check state for the LDAP external server.
  @NotNull private final HealthCheckState healthCheckState;

  // The port number for the LDAP external server.
  private final int serverPort;

  // The address for the LDAP external server.
  @NotNull private final String serverAddress;



  /**
   * Creates a new server availability data object decoded from the provided
   * string.
   *
   * @param  s  The string representation of the
   */
  LoadBalancingAlgorithmServerAvailabilityData(@NotNull final String s)
  {
    final int firstColonPos = s.indexOf(':');
    final int secondColonPos = s.indexOf(':', (firstColonPos+1));

    serverAddress = s.substring(0, firstColonPos);
    serverPort = Integer.parseInt(s.substring(firstColonPos+1, secondColonPos));
    healthCheckState = HealthCheckState.forName(s.substring(secondColonPos+1));
  }



  /**
   * Retrieves the address for the LDAP external server.
   *
   * @return  The address for the LDAP external server.
   */
  @NotNull()
  public String getServerAddress()
  {
    return serverAddress;
  }



  /**
   * Retrieves the port number for the LDAP external server.
   *
   * @return  The port number for the LDAP external server.
   */
  public int getServerPort()
  {
    return serverPort;
  }



  /**
   * Retrieves the health check state for the LDAP external server.
   *
   * @return  The health check state for the LDAP external server.
   */
  @NotNull()
  public HealthCheckState getHealthCheckState()
  {
    return healthCheckState;
  }



  /**
   * Retrieves a string representation of this server availability data object.
   *
   * @return  A string representation of this server availability data object.
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
   * Appends a string representation of this server availability data object to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LoadBalancingAlgorithmServerAvailabilityData(address=");
    buffer.append(serverAddress);
    buffer.append(", port=");
    buffer.append(serverPort);
    buffer.append(", healthCheckState=");
    buffer.append(healthCheckState.name());
    buffer.append(')');
  }



  /**
   * Retrieves a compact representation of the server availability data, in the
   * form in which it appears in the load-balancing algorithm monitor entry.
   *
   * @return  A compact representation of the server availability data.
   */
  @NotNull()
  public String toCompactString()
  {
    return serverAddress + ':' + serverPort + ':' + healthCheckState.name();
  }
}
