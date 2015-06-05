/*
 * Copyright 2007-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This enum defines a set of warning types that may be included in the password
 * policy response control as defined in draft-behera-ldap-password-policy.
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
  private final String name;



  /**
   * Creates a new password policy warning type with the provided name.
   *
   * @param  name The human-readable name for this warning type.
   */
  private PasswordPolicyWarningType(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the human-readable name for this password policy warning type.
   *
   * @return  The human-readable name for this password policy warning type.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a string representation for this password policy warning type.
   *
   * @return  A string representation for this password policy warning type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
