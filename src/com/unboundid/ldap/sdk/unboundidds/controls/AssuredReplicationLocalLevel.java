/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
 * This enum defines an assurance level that may be used for servers in the
 * same location as the server receiving the change.
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
public enum AssuredReplicationLocalLevel
{
  /**
   * Indicates that no local assurance is desired for the associated operation.
   */
  NONE(0),



  /**
   * Indicates that the operation result should not be returned to the client
   * until the change has been received by at least one other replication server
   * in same location.  Note that this level does not require the change to have
   * already been processed by any other directory server, but merely requires
   * that it exist in at least one other replication server for the sake of
   * redundancy.  If the client interacts with another local directory server
   * immediately after receiving a result with this level of assurance, there is
   * no guarantee that the associated change will be visible on that server.
   */
  RECEIVED_ANY_SERVER(1),



  /**
   * Indicates that the operation result should not be returned to the client
   * until the change has been processed by all available directory servers in
   * the same location as the original server.
   */
  PROCESSED_ALL_SERVERS(2);



  // The integer value for this local assurance level.
  private final int intValue;



  /**
   * Creates a new local assurance level with the provided integer value.
   *
   * @param  intValue  The integer value for this local assurance level.
   */
  AssuredReplicationLocalLevel(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves integer value for this local assurance level.
   *
   * @return  The integer value for this local assurance level.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the local assurance level with the specified integer value.
   *
   * @param  intValue  The integer value for the local assurance level to
   *                   retrieve.
   *
   * @return  The requested local assurance level, or {@code null} if there is
   *          no local assurance level with the specified integer value.
   */
  public static AssuredReplicationLocalLevel valueOf(final int intValue)
  {
    for (final AssuredReplicationLocalLevel l : values())
    {
      if (l.intValue == intValue)
      {
        return l;
      }
    }

    return null;
  }



  /**
   * Retrieves the less strict of the two provided assured replication local
   * level values.  If the two provided values are the same, then that value
   * will be returned.
   *
   * @param  l1  The first value to compare.
   * @param  l2  The second value to compare.
   *
   * @return  The less strict of the two provided assured replication local
   *          level values.
   */
  public static AssuredReplicationLocalLevel getLessStrict(
                     final AssuredReplicationLocalLevel l1,
                     final AssuredReplicationLocalLevel l2)
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
   * Retrieves the more strict of the two provided assured replication local
   * level values.  If the two provided values are the same, then that value
   * will be returned.
   *
   * @param  l1  The first value to compare.
   * @param  l2  The second value to compare.
   *
   * @return  The more strict of the two provided assured replication local
   *          level values.
   */
  public static AssuredReplicationLocalLevel getMoreStrict(
                     final AssuredReplicationLocalLevel l1,
                     final AssuredReplicationLocalLevel l2)
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
