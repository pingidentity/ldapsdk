/*
 * Copyright 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides information about the types of alarm severities that may
 * be included in alarm entries.
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
   * @param  name  The name of the alarm severity to retrieve.
   *
   * @return  The alarm severity with the specified name, or {@code null} if
   *          there is no alarm severity with the given name.
   */
  public static AlarmSeverity forName(final String name)
  {
    final String upperName = name.toUpperCase();
    for (final AlarmSeverity s : values())
    {
      if (upperName.equals(s.name()))
      {
        return s;
      }
    }

    return null;
  }
}
