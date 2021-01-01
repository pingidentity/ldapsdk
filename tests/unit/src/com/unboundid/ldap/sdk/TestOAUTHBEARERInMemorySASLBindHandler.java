/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.util.Debug;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides an implementation of a SASL bind handler that can allow
 * the in-memory directory server to simulate support for the OAUTHBEARER SASL
 * mechanism.  When presented with an access token of "success", it will return
 * with a successful bind result.  When presented with an access token of
 * "sasl-bind-in-progress", it will return a {@code SASL_BIND_IN_PROGRESS}
 * result that includes server SASL credentials with failure information.  When
 * presented with any other type of request, it will return a
 * {@code INVALID_CREDENTIALS} result with no server SASL credentials.
 */
public final class TestOAUTHBEARERInMemorySASLBindHandler
       extends InMemorySASLBindHandler
{
  /**
   * Creates a new instance of this SASL bind handler.
   */
  public TestOAUTHBEARERInMemorySASLBindHandler()
  {
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult processSASLBind(final InMemoryRequestHandler handler,
                                    final int messageID, final DN bindDN,
                                    final ASN1OctetString credentials,
                                    final List<Control> controls)
  {
    if (credentials != null)
    {
      try
      {
        final StringTokenizer tokenizer =
             new StringTokenizer(credentials.stringValue(), "\u0001");
        if (tokenizer.hasMoreTokens())
        {
          // The first token will be the GS2 header.  We don't care about it.
          tokenizer.nextToken();

          while (tokenizer.hasMoreTokens())
          {
            final String token = tokenizer.nextToken().toLowerCase();
            if (token.startsWith("auth=bearer "))
            {
              final String accessToken = token.substring(12);
              if (accessToken.equals("success"))
              {
                return new BindResult(messageID, ResultCode.SUCCESS, null,
                     null, null, null, null);
              }
              else if (accessToken.equals("sasl-bind-in-progress"))
              {
                final JSONObject failureDetails = new JSONObject(
                     new JSONField("status", "invalid_token"),
                     new JSONField("scope", "scope1 scope2 scope3"),
                     new JSONField("openid-configuration",
                          "https://openid.example.com/config"),
                     new JSONField("some-other-field", "foo"));
                return new BindResult(messageID,
                     ResultCode.SASL_BIND_IN_PROGRESS, null, null, null, null,
                     new ASN1OctetString(failureDetails.toSingleLineString()));
              }
              else
              {
                break;
              }
            }
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
         "The credentials were not valid", null, null, null, null);
  }
}
