/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
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
       implements HostnameVerifier
{
  /**
   * A singleton instance of this SSL socket verifier.
   */
  @NotNull private static final TrustAllSSLSocketVerifier INSTANCE =
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
  @NotNull()
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
  public void verifySSLSocket(@NotNull final String host, final int port,
                              @NotNull final SSLSocket sslSocket)
       throws LDAPException
  {
    // No implementation is required.  The SSLSocket will be considered
    // acceptable as long as this method does not throw an exception.
  }



  /**
   * Verifies that the provided hostname is acceptable for use with the
   * negotiated SSL session.
   *
   * @param  hostname  The address to which the client intended the connection
   *                   to be established.
   * @param  session   The SSL session that was established.
   */
  @Override()
  public boolean verify(@NotNull final String hostname,
                        @NotNull final SSLSession session)
  {
    return true;
  }
}
