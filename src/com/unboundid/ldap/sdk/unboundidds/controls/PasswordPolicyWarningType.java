/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
 * This enum defines a set of warning types that may be included in the password
 * policy response control as defined in draft-behera-ldap-password-policy.
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
public enum PasswordPolicyWarningType
{
  /**
   * The warning type used to indicate that the user's password will expire in
   * the near future and provide the length of time until it does expire.
   */
  TIME_BEFORE_EXPIRATION("time before expiration"),



  /**
   * The warning type used to indicate that the user's password is expired but
   * that the user may have grace logins remaining, or that a grace login was
   * used in the associated bind.
   */
  GRACE_LOGINS_REMAINING("grace logins remaining");



  // The human-readable name for this password policy warning type.
  @NotNull private final String name;



  /**
   * Creates a new password policy warning type with the provided name.
   *
   * @param  name The human-readable name for this warning type.
   */
  PasswordPolicyWarningType(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the human-readable name for this password policy warning type.
   *
   * @return  The human-readable name for this password policy warning type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the password policy warning type with the specified name.
   *
   * @param  name  The name of the password policy warning type to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested password policy warning type, or {@code null} if no
   *          such type is defined.
   */
  @Nullable()
  public static PasswordPolicyWarningType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "timebeforeexpiration":
      case "time-before-expiration":
      case "time_before_expiration":
      case "time before expiration":
        return TIME_BEFORE_EXPIRATION;
      case "graceloginsremaining":
      case "grace-logins-remaining":
      case "grace_logins_remaining":
      case "grace logins remaining":
        return GRACE_LOGINS_REMAINING;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation for this password policy warning type.
   *
   * @return  A string representation for this password policy warning type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
