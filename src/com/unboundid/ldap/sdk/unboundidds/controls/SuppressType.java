/*
 * Copyright 2012-2018 Ping Identity Corporation
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
 * This enum defines the set of operational update types that may be suppressed
 * by the suppress operational attribute update request control.
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
public enum SuppressType
{
  /**
   * The value that indicates that last access time updates should be
   * suppressed.
   */
  LAST_ACCESS_TIME(0),



  /**
   * The value that indicates that last login time updates should be suppressed.
   */
  LAST_LOGIN_TIME(1),



  /**
   * The value that indicates that last login IP address updates should be
   * suppressed.
   */
  LAST_LOGIN_IP(2),



  /**
   * The value that indicates that lastmod updates (creatorsName,
   * createTimestamp, modifiersName, modifyTimestamp) should be suppressed.
   */
  LASTMOD(3);



  // The integer value for this suppress type enum value.
  private final int intValue;



  /**
   * Creates a new suppress type enum value with the provided information.
   *
   * @param  intValue  The integer value for this value, as will be used to
   *                   indicate it in the request control.
   */
  SuppressType(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this suppress type value.
   *
   * @return  The integer value for this suppress type value.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the suppress type value for the provided integer value.
   *
   * @param  intValue  The integer value for the suppress type value to
                       retrieve.
   *
   * @return  The suppress type value that corresponds to the provided integer
   *          value, or {@code null} if there is no corresponding suppress type
   *          value.
   */
  public static SuppressType valueOf(final int intValue)
  {
    for (final SuppressType t : values())
    {
      if (t.intValue == intValue)
      {
        return t;
      }
    }

    return null;
  }
}
