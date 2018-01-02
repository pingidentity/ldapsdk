/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of error types that may be included in the password
 * policy response control as defined in draft-behera-ldap-password-policy-10.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DraftBeheraLDAPPasswordPolicy10ErrorType
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
  private final String name;



  /**
   * Creates a new password policy error type with the provided information.
   *
   * @param  name   The human-readable name for this error type.
   * @param  value  The numeric value associated with this error type.
   */
  DraftBeheraLDAPPasswordPolicy10ErrorType(final String name, final int value)
  {
    this.name  = name;
    this.value = value;
  }



  /**
   * Retrieves the human-readable name for this password policy error type.
   *
   * @return  The human-readable name for this password policy error type.
   */
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
  public static DraftBeheraLDAPPasswordPolicy10ErrorType
              valueOf(final int intValue)
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
   * Retrieves a string representation for this password policy error type.
   *
   * @return  A string representation for this password policy error type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
