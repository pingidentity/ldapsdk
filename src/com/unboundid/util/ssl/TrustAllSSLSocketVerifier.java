/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import javax.net.ssl.SSLSocket;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an {@code SSLSocket} verifier that
 * will blindly accept any {@code SSLSocket}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TrustAllSSLSocketVerifier
       extends SSLSocketVerifier
{
  /**
   * A singleton instance of this SSL socket verifier.
   */
  private static final TrustAllSSLSocketVerifier INSTANCE =
       new TrustAllSSLSocketVerifier();



  /**
   * Creates a new instance of this {@code SSLSocket} verifier.
   */
  private TrustAllSSLSocketVerifier()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this SSL socket verifier.
   *
   * @return  A singleton instance of this SSL socket verifier.
   */
  public static TrustAllSSLSocketVerifier getInstance()
  {
    return INSTANCE;
  }



  /**
   * Verifies that the provided {@code SSLSocket} is acceptable and the
   * connection should be allowed to remain established.
   *
   * @param  host       The address to which the client intended the connection
   *                    to be established.
   * @param  port       The port to which the client intended the connection to
   *                    be established.
   * @param  sslSocket  The {@code SSLSocket} that should be verified.
   *
   * @throws LDAPException  If a problem is identified that should prevent the
   *                         provided {@code SSLSocket} from remaining
   *                         established.
   */
  @Override()
  public void verifySSLSocket(final String host, final int port,
                              final SSLSocket sslSocket)
       throws LDAPException
  {
    // No implementation is required.  The SSLSocket will be considered
    // acceptable as long as this method does not throw an exception.
  }
}
