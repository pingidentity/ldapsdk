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
 * This enum defines a set of error types that may be included in the password
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
public enum PasswordPolicyErrorType
{
  /**
   * The error type that indicates the user's password is expired.
   */
  PASSWORD_EXPIRED("password expired", 0),



  /**
   * The error type that indicates the user's account is locked or disabled.
   */
  ACCOUNT_LOCKED("account locked", 1),



  /**
   * The error type that indicates the user's password must be changed before
   * any other operation will be allowed.
   */
  CHANGE_AFTER_RESET("change after reset", 2),



  /**
   * The error type that indicates that user password changes aren't allowed.
   */
  PASSWORD_MOD_NOT_ALLOWED("password mod not allowed", 3),



  /**
   * The error type that indicates the user must provide the current password
   * when attempting to set a new one.
   */
  MUST_SUPPLY_OLD_PASSWORD("must supply old password", 4),



  /**
   * The error type that indicates the proposed password is too weak to be
   * acceptable.
   */
  INSUFFICIENT_PASSWORD_QUALITY("insufficient password quality", 5),



  /**
   * The error type that indicates the proposed password is too short.
   */
  PASSWORD_TOO_SHORT("password too short", 6),



  /**
   * The error type that indicates the user's password cannot be changed because
   * it has not been long enough since it was last changed.
   */
  PASSWORD_TOO_YOUNG("password too young", 7),



  /**
   * The error type that indicates the proposed password is already in the
   * password history.
   */
  PASSWORD_IN_HISTORY("password in history", 8);



  // The numeric value associated with this password policy error type.
  private final int value;

  // The human-readable name for this password policy error type.
  @NotNull private final String name;



  /**
   * Creates a new password policy error type with the provided information.
   *
   * @param  name   The human-readable name for this error type.
   * @param  value  The numeric value associated with this error type.
   */
  PasswordPolicyErrorType(@NotNull final String name, final int value)
  {
    this.name  = name;
    this.value = value;
  }



  /**
   * Retrieves the human-readable name for this password policy error type.
   *
   * @return  The human-readable name for this password policy error type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the integer value for this password policy error type.
   *
   * @return  The integer value for this password policy error type.
   */
  public int intValue()
  {
    return value;
  }



  /**
   * Retrieves the password policy error type with the specified int value.
   *
   * @param  intValue  The numeric value associated with the error type.
   *
   * @return  The associated error type, or {@code null} if there is no
   *          password policy error type with the specified set of values.
   */
  @Nullable()
  public static PasswordPolicyErrorType valueOf(final int intValue)
  {
    switch (intValue)
    {
      case 0:
        return PASSWORD_EXPIRED;

      case 1:
        return ACCOUNT_LOCKED;

      case 2:
        return CHANGE_AFTER_RESET;

      case 3:
        return PASSWORD_MOD_NOT_ALLOWED;

      case 4:
        return MUST_SUPPLY_OLD_PASSWORD;

      case 5:
        return INSUFFICIENT_PASSWORD_QUALITY;

      case 6:
        return PASSWORD_TOO_SHORT;

      case 7:
        return PASSWORD_TOO_YOUNG;

      case 8:
        return PASSWORD_IN_HISTORY;

      default:
        return null;
    }
  }



  /**
   * Retrieves the password policy error type with the specified name.
   *
   * @param  name  The name of the password policy error type to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested password policy error type, or {@code null} if no
   *          such type is defined.
   */
  @Nullable()
  public static PasswordPolicyErrorType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "passwordexpired":
      case "password-expired":
      case "password_expired":
      case "password expired":
        return PASSWORD_EXPIRED;
      case "accountlocked":
      case "account-locked":
      case "account_locked":
      case "account locked":
        return ACCOUNT_LOCKED;
      case "changeafterreset":
      case "change-after-reset":
      case "change_after_reset":
      case "change after reset":
        return CHANGE_AFTER_RESET;
      case "passwordmodnotallowed":
      case "password-mod-not-allowed":
      case "password_mod_not_allowed":
      case "password mod not allowed":
        return PASSWORD_MOD_NOT_ALLOWED;
      case "mustsupplyoldpassword":
      case "must-supply-old-password":
      case "must_supply_old_password":
      case "must supply old password":
        return MUST_SUPPLY_OLD_PASSWORD;
      case "insufficientpasswordquality":
      case "insufficient-password-quality":
      case "insufficient_password_quality":
      case "insufficient password quality":
        return INSUFFICIENT_PASSWORD_QUALITY;
      case "passwordtooshort":
      case "password-too-short":
      case "password_too_short":
      case "password too short":
        return PASSWORD_TOO_SHORT;
      case "passwordtooyoung":
      case "password-too-young":
      case "password_too_young":
      case "password too young":
        return PASSWORD_TOO_YOUNG;
      case "passwordinhistory":
      case "password-in-history":
      case "password_in_history":
      case "password in history":
        return PASSWORD_IN_HISTORY;
      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation for this password policy error type.
   *
   * @return  A string representation for this password policy error type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
