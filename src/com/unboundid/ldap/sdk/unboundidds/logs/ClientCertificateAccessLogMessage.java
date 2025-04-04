/*
 * Copyright 2009-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2025 Ping Identity Corporation
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
 * Copyright (C) 2009-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a client
 * certificate that has been presented to the server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ClientCertificateAccessLogMessage
       extends AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2585979292882352926L;



  // The subject DN for the issuer certificate.
  @Nullable private final String issuerSubject;

  // The subject DN for the client certificate.
  @Nullable private final String peerSubject;



  /**
   * Creates a new client certificate access log message from the provided
   * message string.
   *
   * @param  s  The string to be parsed as a client certificate access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public ClientCertificateAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new connect access log message from the provided log message.
   *
   * @param  m  The log message to be parsed as a connect access log message.
   */
  public ClientCertificateAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    peerSubject   = getNamedValue("peerSubject");
    issuerSubject = getNamedValue("issuerSubject");
  }



  /**
   * Retrieves the subject of the peer certificate.
   *
   * @return  The subject of the peer certificate, or {@code null} if it is not
   *          included in the log message.
   */
  @Nullable()
  public String getPeerSubject()
  {
    return peerSubject;
  }



  /**
   * Retrieves the subject of the issuer certificate.
   *
   * @return  The subject of the issuer certificate, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  public String getIssuerSubject()
  {
    return issuerSubject;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.CLIENT_CERTIFICATE;
  }
}
