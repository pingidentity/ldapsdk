/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.
            SecurityNegotiationAccessLogMessage;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides a data structure that holds information about a
 * JSON-formatted security negotiation access log message.
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
public final class JSONSecurityNegotiationAccessLogMessage
       extends JSONAccessLogMessage
       implements SecurityNegotiationAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1857193839548987368L;



  // The set of security negotiation properties for this log message.
  @NotNull private final Map<String,String> negotiationProperties;

  // The cipher for this log message.
  @Nullable private final String cipher;

  // The protocol for this log message.
  @Nullable private final String protocol;



  /**
   * Creates a new JSON security negotiation access log message from the
   * provided JSON object.
   *
   * @param  jsonObject  The JSON object that contains an encoded representation
   *                     of this log message.  It must not be {@code null}.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid log message.
   */
  public JSONSecurityNegotiationAccessLogMessage(
              @NotNull final JSONObject jsonObject)
         throws LogException
  {
    super(jsonObject);

    protocol = getString(JSONFormattedAccessLogFields.PROTOCOL);
    cipher = getString(JSONFormattedAccessLogFields.CIPHER);

    final Map<String,String> propertyMap = new LinkedHashMap<>();
    final List<JSONValue> propertiesObjects = jsonObject.getFieldAsArray(
         JSONFormattedAccessLogFields.SECURITY_NEGOTIATION_PROPERTIES.
              getFieldName());
    if (propertiesObjects != null)
    {
      for (final JSONValue v : propertiesObjects)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject propertyObject = (JSONObject) v;
          final String propertyName =
               propertyObject.getFieldAsString(
                    JSONFormattedAccessLogFields.
                         SECURITY_NEGOTIATION_PROPERTIES_NAME.getFieldName());
          final String propertyValue =
               propertyObject.getFieldAsString(
                    JSONFormattedAccessLogFields.
                         SECURITY_NEGOTIATION_PROPERTIES_VALUE.getFieldName());
          if ((propertyName != null) && (propertyValue != null))
          {
            propertyMap.put(propertyName, propertyValue);
          }
        }
      }
    }

    negotiationProperties = Collections.unmodifiableMap(propertyMap);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.SECURITY_NEGOTIATION;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getProtocol()
  {
    return protocol;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getCipher()
  {
    return cipher;
  }



  /**
   * Retrieves a map with any additional properties that may be associated with
   * the security negotiation.
   *
   * @return  A map with any additional properties that may be associated with
   *          the security negotiation, or an empty map if no negotiation
   *          properties are available.
   */
  @NotNull()
  public Map<String,String> getNegotiationProperties()
  {
    return negotiationProperties;
  }
}
