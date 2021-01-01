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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of access log operation types.
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
public enum AccessLogOperationType
{
  /**
   * The operation type that will be used for messages about abandon operations.
   */
  ABANDON("ABANDON"),



  /**
   * The operation type that will be used for messages about add operations.
   */
  ADD("ADD"),



  /**
   * The operation type that will be used for messages about bind operations.
   */
  BIND("BIND"),



  /**
   * The operation type that will be used for messages about compare operations.
   */
  COMPARE("COMPARE"),



  /**
   * The operation type that will be used for messages about delete operations.
   */
  DELETE("DELETE"),



  /**
   * The operation type that will be used for messages about extended
   * operations.
   */
  EXTENDED("EXTENDED"),



  /**
   * The operation type that will be used for messages about modify operations.
   */
  MODIFY("MODIFY"),



  /**
   * The operation type that will be used for messages about modify DN
   * operations.
   */
  MODDN("MODDN"),



  /**
   * The operation type that will be used for messages about search operations.
   */
  SEARCH("SEARCH"),



  /**
   * The operation type that will be used for messages about unbind operations.
   */
  UNBIND("UNBIND");



  // The string that will be used to identify this message type in log files.
  @NotNull private final String logIdentifier;



  /**
   * Creates a new access log operation type with the provided information.
   *
   * @param  logIdentifier  The string that will be used to identify this
   *                        operation type in log files.
   */
  AccessLogOperationType(@NotNull final String logIdentifier)
  {
    this.logIdentifier = logIdentifier;
  }



  /**
   * Retrieves the string that will be used to identify this operation type in
   * log files.
   *
   * @return  The string that will be used to identify this operation type in
   *          log files.
   */
  @NotNull()
  public String getLogIdentifier()
  {
    return logIdentifier;
  }



  /**
   * Retrieves the access log operation type with the provided identifier.
   *
   * @param  logIdentifier  The identifier string for which to retrieve the
   *                        corresponding access log operation type.
   *
   * @return  The appropriate operation type, or {@code null} if there is no
   *          operation type associated with the provided identifier.
   */
  @Nullable()
  public static AccessLogOperationType forName(
                     @NotNull final String logIdentifier)
  {
    for (final AccessLogOperationType t : values())
    {
      if (t.logIdentifier.equals(logIdentifier))
      {
        return t;
      }
    }

    return null;
  }
}
