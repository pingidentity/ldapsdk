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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of routing types that may be used in a route to
 * backend set request control.
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
public enum RouteToBackendSetRoutingType
{
  /**
   * The routing type that is used for a control which specifies the absolute
   * collection of backend sets to which the request should be forwarded.
   */
  ABSOLUTE_ROUTING((byte) 0xA0),



  /**
   * The routing type that is used for a control which specifies a routing
   * hint to use as a first guess for processing the request and an optional
   * collection of fallback sets.
   */
  ROUTING_HINT((byte) 0xA1);



  // The BER type that corresponds to this enum value.
  private final byte berType;



  /**
   * Creates a new route to backend set routing type value with the provided
   * information.
   *
   * @param  berType  The BER type that corresponds to this enum value.
   */
  RouteToBackendSetRoutingType(final byte berType)
  {
    this.berType = berType;
  }



  /**
   * Retrieves the BER type for this routing type value.
   *
   * @return  The BER type for this routing type value.
   */
  public byte getBERType()
  {
    return berType;
  }



  /**
   * Retrieves the routing type value for the provided BER type.
   *
   * @param  berType  The BER type for the routing type value to retrieve.
   *
   * @return  The routing type value that corresponds to the provided BER type,
   *          or {@code null} if there is no corresponding routing type value.
   */
  @Nullable()
  public static RouteToBackendSetRoutingType valueOf(final byte berType)
  {
    for (final RouteToBackendSetRoutingType t : values())
    {
      if (t.berType == berType)
      {
        return t;
      }
    }

    return null;
  }



  /**
   * Retrieves the route to backend set routing type with the specified name.
   *
   * @param  name  The name of the route to backend set routing type to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested route to backend set routing type, or {@code null}
   *          if no such type is defined.
   */
  @Nullable()
  public static RouteToBackendSetRoutingType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "absoluterouting":
      case "absolute-routing":
      case "absolute_routing":
        return ABSOLUTE_ROUTING;
      case "routinghint":
      case "routing-hint":
      case "routing_hint":
        return ROUTING_HINT;
      default:
        return null;
    }
  }
}
