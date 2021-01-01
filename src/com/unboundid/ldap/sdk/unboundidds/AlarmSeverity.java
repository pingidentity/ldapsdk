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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides information about the types of alarm severities that may
 * be included in alarm entries.
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
public enum AlarmSeverity
{
  /**
   * The alarm severity that indicates that the severity cannot be determined.
   */
  INDETERMINATE,



  /**
   * The alarm severity that indicates that the associated condition is normal.
   */
  NORMAL,



  /**
   * The alarm severity that indicates there is a warning condition.
   */
  WARNING,



  /**
   * The alarm severity that indicates there is a minor error condition.
   */
  MINOR,



  /**
   * The alarm severity that indicates there is a major error condition.
   */
  MAJOR,



  /**
   * The alarm severity that indicates there is a critical error condition.
   */
  CRITICAL;



  /**
   * Retrieves the alarm severity with the specified name.
   *
   * @param  name  The name of the alarm severity to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The alarm severity with the specified name, or {@code null} if
   *          there is no alarm severity with the given name.
   */
  @Nullable()
  public static AlarmSeverity forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "indeterminate":
        return INDETERMINATE;
      case "normal":
        return NORMAL;
      case "warning":
        return WARNING;
      case "minor":
        return MINOR;
      case "major":
        return MAJOR;
      case "critical":
        return CRITICAL;
      default:
        return null;
    }
  }
}
