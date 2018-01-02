/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of validation level values that may be used in
 * conjunction with the {@link UniquenessRequestControl}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
}
