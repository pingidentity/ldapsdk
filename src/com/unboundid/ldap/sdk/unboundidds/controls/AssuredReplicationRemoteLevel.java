/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
 * This enum defines an assurance level that may be used for servers in
 * different locations from the server receiving the change.
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
public enum AssuredReplicationRemoteLevel
{
  /**
   * Indicates that no remote assurance is desired for the associated operation.
   */
  NONE(0),



  /**
   * Indicates that the operation result should not be returned to the client
   * until the change has been received by at least one replication server in a
   * different location.  Note that this level does not require the change to
   * have already been processed by any other directory server, but merely
   * requires that it exist in at least one remote replication server for the
   * sake of redundancy.  If the client interacts with another remote directory
   * server immediately after receiving a result with this level of assurance,
   * there is no guarantee that the associated change will be visible on that
   * server.
   */
  RECEIVED_ANY_REMOTE_LOCATION(1),



  /**
   * Indicates that the operation result should not be returned to the client
   * until the change has been received by at least one replication server in
   * each of the remote locations.  Note that this level does not require the
   * change to have already been processed by any other directory server, but
   * merely requires that it exist in at least one remote replication server in
   * each remote location for the sake of redundancy.  If the client interacts
   * with another remote directory server immediately after receiving a result
   * with this level of assurance, there is no guarantee that the associated
   * change will be visible on that server.
   */
  RECEIVED_ALL_REMOTE_LOCATIONS(2),



  /**
   * Indicates that the operation result should not be returned to the client
   * until the change has been processed by all available servers in all remote
   * locations.
   */
  PROCESSED_ALL_REMOTE_SERVERS(3);



  // The integer value for this remote assurance level.
  private final int intValue;



  /**
   * Creates a new remote assurance level with the provided integer value.
   *
   * @param  intValue  The integer value for this remote assurance level.
   */
  AssuredReplicationRemoteLevel(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves integer value for this remote assurance level.
   *
   * @return  The integer value for this remote assurance level.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the remote assurance level with the specified integer value.
   *
   * @param  intValue  The integer value for the remote assurance level to
   *                   retrieve.
   *
   * @return  The requested remote assurance level, or {@code null} if there is
   *          no remote assurance level with the specified integer value.
   */
  @Nullable()
  public static AssuredReplicationRemoteLevel valueOf(final int intValue)
  {
    for (final AssuredReplicationRemoteLevel l : values())
    {
      if (l.intValue == intValue)
      {
        return l;
      }
    }

    return null;
  }



  /**
   * Retrieves the remote assurance level with the specified name.
   *
   * @param  name  The name of the remote assurance level to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The requested remote assurance level, or {@code null} if no such
   *          level is defined.
   */
  @Nullable()
  public static AssuredReplicationRemoteLevel forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "none":
        return NONE;
      case "receivedanyremotelocation":
      case "received-any-remote-location":
      case "received_any_remote_location":
        return RECEIVED_ANY_REMOTE_LOCATION;
      case "receivedallremotelocations":
      case "received-all-remote-locations":
      case "received_all_remote_locations":
        return RECEIVED_ALL_REMOTE_LOCATIONS;
      case "processedallremoteservers":
      case "processed-all-remote-servers":
      case "processed_all_remote_servers":
        return PROCESSED_ALL_REMOTE_SERVERS;
      default:
        return null;
    }
  }



  /**
   * Retrieves the less strict of the two provided assured replication remote
   * level values.  If the two provided values are the same, then that value
   * will be returned.
   *
   * @param  l1  The first value to compare.
   * @param  l2  The second value to compare.
   *
   * @return  The less strict of the two provided assured replication remote
   *          level values.
   */
  @NotNull()
  public static AssuredReplicationRemoteLevel getLessStrict(
                     @NotNull final AssuredReplicationRemoteLevel l1,
                     @NotNull final AssuredReplicationRemoteLevel l2)
  {
    // At present, the integer values can be used to make the comparison.  If
    // any more enum values are added, this may need to be changed.
    if (l1.intValue <= l2.intValue)
    {
      return l1;
    }
    else
    {
      return l2;
    }
  }



  /**
   * Retrieves the more strict of the two provided assured replication remote
   * level values.  If the two provided values are the same, then that value
   * will be returned.
   *
   * @param  l1  The first value to compare.
   * @param  l2  The second value to compare.
   *
   * @return  The more strict of the two provided assured replication remote
   *          level values.
   */
  @NotNull()
  public static AssuredReplicationRemoteLevel getMoreStrict(
                     @NotNull final AssuredReplicationRemoteLevel l1,
                     @NotNull final AssuredReplicationRemoteLevel l2)
  {
    // At present, the integer values can be used to make the comparison.  If
    // any more enum values are added, this may need to be changed.
    if (l1.intValue >= l2.intValue)
    {
      return l1;
    }
    else
    {
      return l2;
    }
  }
}
