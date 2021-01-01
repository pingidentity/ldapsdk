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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides information about the types of alert severities that may
 * be included in alert entries.
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
public enum AlertSeverity
{
  /**
   * The alert severity that indicates that the associated alert is
   * informational.
   */
  INFO("info"),



  /**
   * The alert severity that indicates that the associated alert indicates a
   * warning has occurred.
   */
  WARNING("warning"),



  /**
   * The alert severity that indicates that the associated alert indicates a
   * non-fatal error has occurred.
   */
  ERROR("error"),



  /**
   * The alert severity that indicates that the associated alert indicates a
   * fatal error has occurred.
   */
  FATAL("fatal");



  // The name for this alert severity.
  @NotNull private final String name;



  /**
   * Creates a new alert severity with the specified name.
   *
   * @param  name  The name for this alert severity.
   */
  AlertSeverity(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name for this alert severity.
   *
   * @return  The name for this alert severity.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the alert severity with the specified name.
   *
   * @param  name  The name of the alert severity to retrieve.
   *
   * @return  The alert severity with the specified name, or {@code null} if
   *          there is no alert severity with the given name.
   */
  @Nullable()
  public static AlertSeverity forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "info":
        return INFO;
      case "warning":
        return WARNING;
      case "error":
        return ERROR;
      case "fatal":
        return FATAL;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this alert severity.
   *
   * @return  A string representation of this alert severity.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
