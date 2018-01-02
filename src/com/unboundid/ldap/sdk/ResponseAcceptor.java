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
package com.unboundid.ldap.sdk;



import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface is used by classes which are able to receive an LDAP response
 * read from the server.
 */
@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
interface ResponseAcceptor
{
  /**
   * Indicates that the provided LDAP response has been received by from the
   * server.
   *
   * @param  response  The LDAP response that has been received from the server.
   *                   It may be {@code null} if the connection has been closed
   *                   without having received any response.
   *
   * @throws  LDAPException  If a problem occurs while handling the response.
   */
  void responseReceived(LDAPResponse response)
       throws LDAPException;
}
