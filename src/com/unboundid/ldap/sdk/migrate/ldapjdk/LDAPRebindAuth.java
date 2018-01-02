/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that may be used when authenticating a
 * connection used to follow a referral.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.ReferralConnector} class should be used
 * instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPRebindAuth
       implements Serializable
{
  /**
   * The serial version UID to use for this serializable class.
   */
  private static final long serialVersionUID = -844389460595019929L;



  // The DN to use when authenticating.
  private final String dn;

  // The password to use when authenticating.
  private final String password;



  /**
   * Creates a new LDAP rebind auth object with the provided information.
   *
   * @param  dn        The DN to use when authenticating.
   * @param  password  The password to use when authenticating.
   */
  public LDAPRebindAuth(final String dn, final String password)
  {
    this.dn       = dn;
    this.password = password;
  }



  /**
   * Retrieves the DN to use when authenticating.
   *
   * @return  The DN to use when authenticating.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the password to use when authenticating.
   *
   * @return  The password to use when authenticating.
   */
  public String getPassword()
  {
    return password;
  }
}
