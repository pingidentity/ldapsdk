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
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that will be invoked immediately after establishing
 * a connection using {@code SSLSocket} (whether by establishing a connection
 * that is initially secure or by wrapping an existing insecure connection in an
 * {@code SSLSocket}).  It may be used to terminate the connection if it is
 * determined that the connection should not be trusted for some reason.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class SSLSocketVerifier
{
  /**
   * Verifies that the provided {@code SSLSocket} is acceptable and the
   * connection should be allowed to remain established.
   *
   * @param  host              The address to which the client intended the
   *                           connection to be established.
   * @param  port              The port to which the client intended the
   *                           connection to be established.
   * @param  sslSocket         The {@code SSLSocket} that was created and should
   *                           be verified.
   *
   * @throws  LDAPException  If a problem is identified that should prevent the
   *                         provided {@code SSLSocket} from remaining
   *                         established.
   */
  public abstract void verifySSLSocket(String host, int port,
                                       SSLSocket sslSocket)
         throws LDAPException;
}
