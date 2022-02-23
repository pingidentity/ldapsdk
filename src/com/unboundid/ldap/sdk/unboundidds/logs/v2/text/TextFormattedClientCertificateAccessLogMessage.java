/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            ClientCertificateAccessLogMessage;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a
 * text-formatted client certificate access log message.
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
public final class TextFormattedClientCertificateAccessLogMessage
       extends TextFormattedAccessLogMessage
       implements ClientCertificateAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4303971125611290508L;



  // The list of subject DNs for the issuer certificates.
  @NotNull private final List<String> issuerSubjectDNs;

  // The auto-authenticated as DN for this log message.
  @Nullable private final String autoAuthenticatedAsDN;

  // The subject DN for the peer certificate
  @Nullable private final String peerSubjectDN;



  /**
   * Creates a new text-formatted client certificate access log message from the
   * provided message string.
   *
   * @param  logMessageString  The string representation of this log message.
   *                           It must not be {@code null}.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public TextFormattedClientCertificateAccessLogMessage(
              @NotNull final String logMessageString)
         throws LogException
  {
    this(new TextFormattedLogMessage(logMessageString));
  }



  /**
   * Creates a new text-formatted client certificate access log message from the
   * provided message.
   *
   * @param  logMessage  The log message to use to create this client
   *                     certificate access log message.  It must not be
   *                     {@code null}.
   */
  TextFormattedClientCertificateAccessLogMessage(
       @NotNull final TextFormattedLogMessage logMessage)
  {
    super(logMessage);

    peerSubjectDN =
         getString(TextFormattedAccessLogFields.PEER_CERTIFICATE_SUBJECT_DN);
    autoAuthenticatedAsDN =
         getString(TextFormattedAccessLogFields.AUTO_AUTHENTICATED_AS);

    final List<String> issuerDNs = getFields().get(TextFormattedAccessLogFields.
         ISSUER_CERTIFICATE_SUBJECT_DN.getFieldName());
    if (issuerDNs == null)
    {
      issuerSubjectDNs = Collections.emptyList();
    }
    else
    {
      issuerSubjectDNs = issuerDNs;
    }
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



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getPeerSubjectDN()
  {
    return peerSubjectDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getIssuerSubjectDNs()
  {
    return issuerSubjectDNs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getAutoAuthenticatedAsDN()
  {
    return autoAuthenticatedAsDN;
  }
}
