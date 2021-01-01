/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
 * This enum defines the set of validation level values that may be used in
 * conjunction with the {@link UniquenessRequestControl}.
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
public enum UniquenessValidationLevel
{
  /**
   * Indicates that no uniqueness validation should be performed.  This
   * validation level has the same effect for requests sent directly to a
   * Directory Server and requests sent through a Directory Proxy Server.
   */
  NONE(0),



  /**
   * Indicates that a single search should be performed per subtree view to
   * ensure that there are no uniqueness conflicts.  This has the following
   * behavior:
   * <UL>
   *   <LI>
   *     If the request is received by a Directory Server instance, then only
   *     that instance will be searched for potential conflicts.  No replicas
   *     will be examined.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     does not use entry balancing, then only one backend server will be
   *     searched for potential conflicts.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     uses entry balancing, then the server may only search one backend
   *     server in one backend set if it can use its global index to identify
   *     which backend set is appropriate.  However, if the scope of the
   *     uniqueness request control contains the entire set of entry-balanced
   *     data and the global index does not include enough information to
   *     restrict the search to one backend set, then it may be necessary to
   *     issue the search to one server in each backend set.
   *   </LI>
   * </UL>
   */
  ALL_SUBTREE_VIEWS(1),



  /**
   * Indicates that one server from each entry-balanced backend set should be
   * searched for potential uniqueness conflicts.  This has the following
   * behavior:
   * <UL>
   *   <LI>
   *     If the request is received by a Directory Server instance, then only
   *     that instance will be searched for potential conflicts.  No replicas
   *     will be examined.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     does not use entry balancing, then only one backend server will be
   *     searched for potential conflicts.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     uses entry balancing and the scope of the uniqueness request control
   *     covers the entire set of entry-balanced data, then one server from each
   *     backend set will be searched for potential conflicts.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     uses entry balancing, and if the uniqueness request control has a base
   *     DN that is below the balancing point, and if the server's global index
   *     can be used to identify which backend set contains the entry with that
   *     DN, then it may only be necessary to search within that one backend
   *     set, and only within one server in that set.  However, if the global
   *     index cannot be used to identify the appropriate backend set, then it
   *     may be necessary to search one server in each backend set.
   *   </LI>
   * </UL>
   */
  ALL_BACKEND_SETS(2),



  /**
   * Indicates that all available servers within the scope of the uniqueness
   * criteria should be searched for potential uniqueness conflicts.  This has
   * the following behavior:
   * <UL>
   *   <LI>
   *     If the request is received by a Directory Server instance, then only
   *     that instance will be searched for potential conflicts.  No replicas
   *     will be examined.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     does not use entry balancing, then all backend servers with a health
   *     check state of "AVAILABLE" will be searched for potential conflicts.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     uses entry balancing and the scope of the uniqueness request control
   *     covers the entire set of entry-balanced data, then all backend servers
   *     with a health check state of "AVAILABLE" will be searched for
   *     potential conflicts, across all backend sets.
   *   </LI>
   *   <LI>
   *     If the request is received by a Directory Proxy Server instance that
   *     uses entry balancing, and if the uniqueness request control has a base
   *     DN that is below the balancing point, and if the server's global index
   *     can be used to identify which backend set contains the entry with that
   *     DN, then it may only be necessary to search all available servers
   *     within that one backend set.  However, if the global index cannot be
   *     used to identify the appropriate backend set, then it may be necessary
   *     to search all available servers in all backend sets.
   *   </LI>
   * </UL>
   */
  ALL_AVAILABLE_BACKEND_SERVERS(3);



  // The integer value for this uniqueness validation level.
  private final int intValue;



  /**
   * Creates a new uniqueness validation level with the provided integer value.
   *
   * @param  intValue  The integer value for this uniqueness validation level.
   */
  UniquenessValidationLevel(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this uniqueness validation level.
   *
   * @return  The integer value for this uniqueness validation level.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the uniqueness validation level with the specified integer value.
   *
   * @param  intValue  The integer value for the uniqueness validation level to
   *                   retrieve.
   *
   * @return  The uniqueness validation level for the provided integer value, or
   *          {@code null} if there is no validation level with the given
   *          integer value.
   */
  @Nullable()
  public static UniquenessValidationLevel valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return NONE;
      case 1:
        return ALL_SUBTREE_VIEWS;
      case 2:
        return ALL_BACKEND_SETS;
      case 3:
        return ALL_AVAILABLE_BACKEND_SERVERS;
      default:
        return null;
    }
  }



  /**
   * Retrieves the uniqueness validation level with the specified name.
   *
   * @param  name  The name of the uniqueness validation level to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested uniqueness validation level, or {@code null} if no
   *          such level is defined.
   */
  @Nullable()
  public static UniquenessValidationLevel forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "none":
        return NONE;
      case "allsubtreeviews":
      case "all-subtree-views":
      case "all_subtree_views":
        return ALL_SUBTREE_VIEWS;
      case "allbackendsets":
      case "all-backend-sets":
      case "all_backend_sets":
        return ALL_BACKEND_SETS;
      case "allavailablebackendservers":
      case "all-available-backend-servers":
      case "all_available_backend_servers":
        return ALL_AVAILABLE_BACKEND_SERVERS;
      default:
        return null;
    }
  }
}
