/*
 * Copyright 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPExtendedOperationException;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a post-connect processor that can be
 * used to start an administrative session on a connection that is meant to be
 * part of a connection pool.  If this is to be used in conjunction with other
 * post-connect processors (via the
 * {@link com.unboundid.ldap.sdk.AggregatePostConnectProcessor}), then the
 * start administrative session processor should generally be invoked first
 * (even before the
 * {@link com.unboundid.ldap.sdk.StartTLSPostConnectProcessor}) to ensure that
 * any interaction with the server will be able to make use of the dedicated
 * worker thread pool the server sets aside for operations using an
 * administrative session.
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
public final class StartAdministrativeSessionPostConnectProcessor
       implements PostConnectProcessor, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3327980552475726214L;



  // The start administrative session extended request to be invoked for
  // newly-established connections.
  private final StartAdministrativeSessionExtendedRequest request;



  /**
   * Creates a new start administrative session post-connect processor that will
   * issue the provided extended request over a newly-established connection.
   *
   * @param  request  The start administrative session extended request to be
   *                  invoked for newly-established connections.
   */
  public StartAdministrativeSessionPostConnectProcessor(
              final StartAdministrativeSessionExtendedRequest request)
  {
    this.request = request;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    final ExtendedResult result =
         connection.processExtendedOperation(request.duplicate());
    if (result.getResultCode() != ResultCode.SUCCESS)
    {
      throw new LDAPExtendedOperationException(result);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPostAuthenticatedConnection(
                   final LDAPConnection connection)
         throws LDAPException
  {
    // No implementation is required.
  }
}
