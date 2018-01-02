/*
 * Copyright 2007-2018 Ping Identity Corporation
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



import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

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
 * // Configure an SSLUtil instance and use it to obtain an SSLContext.
 * SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
 * SSLContext sslContext = sslUtil.createSSLContext();
 *
 * // Establish an insecure connection to the directory server.
 * LDAPConnection connection = new LDAPConnection(serverAddress, nonSSLPort);
 *
 * // Use the StartTLS extended operation to secure the connection.
 * ExtendedResult startTLSResult = connection.processExtendedOperation(
 *      new StartTLSExtendedRequest(sslContext));
 *
 * // Create a connection pool that will secure its connections with StartTLS.
 * BindResult bindResult = connection.bind(
 *      "uid=john.doe,ou=People,dc=example,dc=com", "password");
 * StartTLSPostConnectProcessor startTLSProcessor =
 *      new StartTLSPostConnectProcessor(sslContext);
 * LDAPConnectionPool pool =
 *      new LDAPConnectionPool(connection, 1, 10, startTLSProcessor);
 *
 * // Verify that we can use the pool to communicate with the directory server.
 * RootDSE rootDSE = pool.getRootDSE();
 *
 * // Close the connection pool.
 * pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StartTLSPostConnectProcessor
       implements PostConnectProcessor
{
  // The SSL context to use to perform the negotiation.
  private final SSLContext sslContext;

  // The SSL socket factory to create the secure connection.
  private final SSLSocketFactory sslSocketFactory;



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
    sslSocketFactory = null;
  }



  /**
   * Creates a new instance of this StartTLS post-connect processor that will
   * use the provided SSL context.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to create the
   *                           TLS-secured socket.  It must not be {@code null}.
   */
  public StartTLSPostConnectProcessor(final SSLSocketFactory sslSocketFactory)
  {
    ensureNotNull(sslSocketFactory);

    this.sslSocketFactory = sslSocketFactory;
    sslContext = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    final StartTLSExtendedRequest startTLSRequest;
    if (sslContext == null)
    {
      startTLSRequest = new StartTLSExtendedRequest(sslSocketFactory);
    }
    else
    {
      startTLSRequest = new StartTLSExtendedRequest(sslContext);
    }

    // Since the StartTLS processing will occur during the course of
    // establishing the connection for use in the pool, set the connect timeout
    // for the operation to be equal to the connect timeout from the connection
    // options.
    final LDAPConnectionOptions opts = connection.getConnectionOptions();
    startTLSRequest.setResponseTimeoutMillis(opts.getConnectTimeoutMillis());

    final ExtendedResult r =
         connection.processExtendedOperation(startTLSRequest);
    if (! r.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPExtendedOperationException(r);
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
    // No implementation is required for this post-connect processor.
  }
}
