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
 * This enum defines the set of result code values that may be included in a
 * an assured replication server result.
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
  @Nullable()
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



  /**
   * Retrieves the assured replication server result code with the specified
   * name.
   *
   * @param  name  The name of the assured replication server result code to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested assured replication server result code, or
   *          {@code null} if no such result code is defined.
   */
  @Nullable()
  public static AssuredReplicationServerResultCode forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "complete":
        return COMPLETE;
      case "timeout":
        return TIMEOUT;
      case "conflict":
        return CONFLICT;
      case "servershutdown":
      case "server-shutdown":
      case "server_shutdown":
        return SERVER_SHUTDOWN;
      case "unavailable":
        return UNAVAILABLE;
      case "duplicate":
        return DUPLICATE;
      default:
        return null;
    }
  }
}
