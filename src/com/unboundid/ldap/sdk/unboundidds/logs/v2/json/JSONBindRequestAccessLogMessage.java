/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.ldap.sdk.unboundidds.logs.BindRequestAuthenticationType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.BindRequestAccessLogMessage;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted bind request access log message.
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
public class JSONBindRequestAccessLogMessage
       extends JSONRequestAccessLogMessage
       implements BindRequestAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6983414352725940767L;



  // The authentication type for the bind request.
  @Nullable private final BindRequestAuthenticationType authenticationType;

  // The bind DN for the bind request.
  @Nullable private final String dn;

  // The protocol version for the bind request.
  @Nullable private final String protocolVersion;

  // The SASL mechanism name for the bind request.
  @Nullable private final String saslMechanismName;



  /**
   * Creates a new JSON bind request access log message from the provided
   * JSON object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  public JSONBindRequestAccessLogMessage(@NotNull final JSONObject jsonObject)
         throws LogException
  {
    super(jsonObject);

    dn = getString(JSONFormattedAccessLogFields.BIND_DN);
    protocolVersion =
         getString(JSONFormattedAccessLogFields.BIND_PROTOCOL_VERSION);
    saslMechanismName =
         getString(JSONFormattedAccessLogFields.BIND_SASL_MECHANISM);

    final String authType =
         getString(JSONFormattedAccessLogFields.BIND_AUTHENTICATION_TYPE);
    if (authType == null)
    {
      authenticationType = null;
    }
    else
    {
      authenticationType = BindRequestAuthenticationType.forName(authType);
    }
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



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final BindRequestAuthenticationType getAuthenticationType()
  {
    return authenticationType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getDN()
  {
    return dn;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getProtocolVersion()
  {
    return protocolVersion;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getSASLMechanismName()
  {
    return saslMechanismName;
  }
}
