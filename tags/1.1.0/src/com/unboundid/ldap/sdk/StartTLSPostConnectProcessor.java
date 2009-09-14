/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import javax.net.ssl.SSLContext;

import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of a post-connect processor that can
 * be used to perform StartTLS negotiation on an LDAP connection that is
 * intended to be used in a connection pool.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the StartTLS post-connect
 * processor to create an LDAP connection pool whose connections are secured
 * using StartTLS:
 * <PRE>
 *   SSLUtil sslUtil =
 *        new SSLUtil(new TrustStoreTrustManager("/my/trust/store/file"));
 *   SSLContext sslContext = sslUtil.createSSLContext();
 *
 *   LDAPConnection connection = new LDAPConnection("server.example.com", 389);
 *   ExtendedResult startTLSResult = connection.processExtendedOperation(
 *        new StartTLSExtendedOperation(sslContext);
 *   BindResult bindResult = connection.bind(
 *        "uid=john.doe,ou=People,dc=example,dc=com", "password");
 *
 *   StartTLSPostConnectProcessor startTLSProcessor =
 *        new StartTLSPostConnectProcessor(sslContext);
 *   LDAPConnectionPool pool =
 *        new LDAPConnectionPool(connection, 1, 10, startTLSProcessor);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StartTLSPostConnectProcessor
       implements PostConnectProcessor
{
  // The SSL context to use to perform the negotiation.
  private final SSLContext sslContext;



  /**
   * Creates a new instance of this StartTLS post-connect processor that will
   * use the provided SSL context.
   *
   * @param  sslContext  The SSL context to use to perform the StartTLS
   *                     negotiation.  It must not be {@code null}.
   */
  public StartTLSPostConnectProcessor(final SSLContext sslContext)
  {
    ensureNotNull(sslContext);

    this.sslContext = sslContext;
  }



  /**
   * {@inheritDoc}
   */
  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    final ExtendedResult r = connection.processExtendedOperation(
         new StartTLSExtendedRequest(sslContext));
    if (! r.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPException(r);
    }
  }



  /**
   * {@inheritDoc}
   */
  public void processPostAuthenticatedConnection(
                   final LDAPConnection connection)
         throws LDAPException
  {
    // No implementation is required for this post-connect processor.
  }
}
