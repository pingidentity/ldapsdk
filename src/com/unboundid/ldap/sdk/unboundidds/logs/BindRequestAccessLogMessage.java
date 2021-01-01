/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about a bind
 * request received from a client.
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
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class BindRequestAccessLogMessage
       extends OperationRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8603928027823970L;



  // The type of authentication requested by the client.
  @Nullable private final BindRequestAuthenticationType authenticationType;

  // The DN of the user attempting to bind.
  @Nullable private final String dn;

  // The string representation of the protocol version.
  @Nullable private final String protocolVersion;

  // The name of the SASL mechanism requested by the client.
  @Nullable private final String saslMechanismName;



  /**
   * Creates a new bind request access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as an bind request access log
   *            message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public BindRequestAccessLogMessage(@NotNull final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new bind request access log message from the provided message
   * string.
   *
   * @param  m  The log message to be parsed as a bind request access log
   *            message.
   */
  public BindRequestAccessLogMessage(@NotNull final LogMessage m)
  {
    super(m);

    dn                = getNamedValue("dn");
    saslMechanismName = getNamedValue("saslMechanism");
    protocolVersion   = getNamedValue("version");

    BindRequestAuthenticationType authType = null;
    try
    {
      authType =
           BindRequestAuthenticationType.valueOf(getNamedValue("authType"));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
    authenticationType = authType;
  }



  /**
   * Retrieves the type of authentication requested by the client.
   *
   * @return  The type of authentication requested by the client, or
   *          {@code null} if it is not included in the log message.
   */
  @Nullable()
  public final BindRequestAuthenticationType getAuthenticationType()
  {
    return authenticationType;
  }



  /**
   * Retrieves the DN of the user attempting to bind.  This value may not be
   * useful for authentication types other than "SIMPLE".
   *
   * @return  The DN of the user attempting to bind, or {@code null} if it is
   *          not included in the log message.
   */
  @Nullable()
  public final String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the protocol version for the bind request.
   *
   * @return  The protocol version for the bind request, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  public final String getProtocolVersion()
  {
    return protocolVersion;
  }



  /**
   * Retrieves the name of the requested SASL mechanism.  This should only be
   * included for SASL bind attempts.
   *
   * @return  The name of the requested SASL mechanism, or {@code null} if it
   *          is not included in the log message.
   */
  @Nullable()
  public final String getSASLMechanismName()
  {
    return saslMechanismName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final AccessLogOperationType getOperationType()
  {
    return AccessLogOperationType.BIND;
  }
}
