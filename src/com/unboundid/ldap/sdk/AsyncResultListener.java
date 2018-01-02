/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface provides a mechanism for notifying a client when the result
 * for an asynchronous operation has been received.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface AsyncResultListener
{
  /**
   * Indicates that the provided LDAP result has been received in response to an
   * asynchronous operation.  Note that automatic referral following is not
   * supported for asynchronous operations, so it is possible that this result
   * could include a referral.
   *
   * @param  requestID   The async request ID of the request for which the
   *                     response was received.
   * @param  ldapResult  The LDAP result that has been received.
   */
  void ldapResultReceived(AsyncRequestID requestID, LDAPResult ldapResult);
}
