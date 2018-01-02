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
 * This enum defines the set of result code values that may be included in a
 * an assured replication server result.
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
public enum AssuredReplicationServerResultCode
{
  /**
   * Indicates that the requested level of assurance was successfully attained.
   */
  COMPLETE(0),



  /**
   * Indicates that the requested level of assurance could not be attained
   * before the timeout elapsed.
   */
  TIMEOUT(1),



  /**
   * Indicates that a replication conflict was encountered that will prevent
   * the associated operation from being applied to the target server.
   */
  CONFLICT(2),



  /**
   * Indicates that the target server was shut down while waiting for an
   * assurance result.
   */
  SERVER_SHUTDOWN(3),



  /**
   * Indicates that the target server became unavailable while waiting for an
   * assurance result.
   */
  UNAVAILABLE(4),



  /**
   * Indicates that the replication assurance engine detected a duplicate
   * request for the same operation.
   */
  DUPLICATE(5);



  // The integer value for this server result code.
  private final int intValue;



  /**
   * Creates a new assured replication server result code with the specified
   * integer value.
   *
   * @param  intValue  The integer value for this assured replication server
   *                   result code.
   */
  AssuredReplicationServerResultCode(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this assured replication server result
   * code.
   *
   * @return  The integer value for this assured replication server result code.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the assured replication server result code with the specified
   * integer value.
   *
   * @param  intValue  The integer value for the server result code to
   *                   retrieve.
   *
   * @return  The requested assured replication server result code, or
   *          {@code null} if there is no server result code with the specified
   *          integer value.
   */
  public static AssuredReplicationServerResultCode valueOf(final int intValue)
  {
    for (final AssuredReplicationServerResultCode rc : values())
    {
      if (rc.intValue == intValue)
      {
        return rc;
      }
    }

    return null;
  }
}
