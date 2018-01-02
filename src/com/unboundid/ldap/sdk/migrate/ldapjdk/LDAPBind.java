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



import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a method that can be used to bind to a server when
 * following a referral.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.ReferralConnector} class should be used
 * instead.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDAPBind
{
  /**
   * Authenticates the provided connection created for the purpose of following
   * a referral.
   *
   * @param  conn  The connection to be authenticated.
   *
   * @throws  LDAPException  If a problem occurs while processing the bind.
   */
  void bind(LDAPConnection conn)
       throws LDAPException;
}
