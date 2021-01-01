/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
 * This enum defines the set of operational update types that may be suppressed
 * by the suppress operational attribute update request control.
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
  @Nullable()
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



  /**
   * Retrieves the suppress type with the specified name.
   *
   * @param  name  The name of the suppress type to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested suppress type, or {@code null} if no such type is
   *          defined.
   */
  @Nullable()
  public static SuppressType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "lastaccesstime":
      case "last-access-time":
      case "last_access_time":
        return LAST_ACCESS_TIME;
      case "lastlogintime":
      case "last-login-time":
      case "last_login_time":
        return LAST_LOGIN_TIME;
      case "lastloginip":
      case "last-login-ip":
      case "last_login_ip":
        return LAST_LOGIN_IP;
      case "lastmod":
        return LASTMOD;
      default:
        return null;
    }
  }
}
