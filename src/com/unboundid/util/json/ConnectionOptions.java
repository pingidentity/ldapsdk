/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.io.Serializable;

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;



/**
 * This class provides a data structure and set of logic for interacting with
 * the set of connection options in a JSON object provided to the
 * {@link LDAPConnectionDetailsJSONSpecification}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class ConnectionOptions
      implements Serializable
{
  /**
   * The name of the field that specifies the maximum length of time (in
   * milliseconds) to wait for a connection to be established.  If present, the
   * value should be a positive integer, or zero to indicate that no connect
   * timeout should be enforced for the LDAP SDK.  If it is absent, then a
   * default of 60000 (1 minute) will be used.
   */
  @NotNull private static final String FIELD_CONNECT_TIMEOUT_MILLIS =
       "connect-timeout-millis";



  /**
   * The name of the field that specifies the default maximum length of time (in
   * milliseconds) to wait for a response to an LDAP request.  If present, the
   * value should be a positive integer, or zero to indicate that no default
   * response timeout will be enforced.  If it is absent, then a default of
   * 300000 (5 minutes) will be used.  This response timeout can be overridden
   * on a per-operation basis.
   */
  @NotNull private static final String FIELD_DEFAULT_RESPONSE_TIMEOUT_MILLIS =
       "default-response-timeout-millis";



  /**
   * The name of the field that indicates whether to attempt to automatically
   * follow any referrals that are returned by the server.  If present, the
   * value should be a boolean.  If it is absent, then a default of
   * {@code false} will be used.
   */
  @NotNull private static final String FIELD_FOLLOW_REFERRALS =
       "follow-referrals";



  /**
   * The name of the field that indicates whether to retrieve schema information
   * from the directory server for use in more accurate client-side matching
   * operations.  If it is present, then value should be a boolean.  If it is
   * absent, then a default of {@code false} will be used.
   */
  @NotNull private static final String FIELD_USE_SCHEMA = "use-schema";



  /**
   * The name of the field that indicates whether to create connections that
   * operate in synchronous mode, in which the thread that issues a request will
   * be used to read the response.  This can be more lightweight and provide
   * better performance, but can only be used if there will not be any attempts
   * to process asynchronous operations or use the same connection
   * simultaneously by multiple threads for multiple concurrent operations.  If
   * it is present, then the value should be a boolean.  If it is absent, then a
   * default of {@code false} will be used.
   */
  @NotNull private static final String FIELD_USE_SYNCHRONOUS_MODE =
       "use-synchronous-mode";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4615610794723107852L;



  // Indicates whether to use follow referrals.
  private final boolean followReferrals;

  // Indicates whether to use schema.
  private final boolean useSchema;

  // Indicates whether to use synchronous mode.
  private final boolean useSynchronousMode;

  // The default connect timeout in milliseconds.
  private final int connectTimeoutMillis;

  // The default response timeout in milliseconds.
  private final long defaultResponseTimeoutMillis;



  /**
   * Creates a new set of connection options from the information contained in
   * the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object containing the LDAP
   *                                  connection details specification.
   *
   * @throws LDAPException  If there is a problem with the connection options
   *                         data in the provided JSON object.
   */
  ConnectionOptions(@NotNull final JSONObject connectionDetailsObject)
       throws LDAPException
  {
    boolean referrals = false;
    boolean schema = false;
    boolean synchronous = false;
    int connect = 60_000;
    long response = 300_000L;

    final JSONObject o = LDAPConnectionDetailsJSONSpecification.getObject(
         connectionDetailsObject,
         LDAPConnectionDetailsJSONSpecification.FIELD_CONNECTION_OPTIONS);
    if (o != null)
    {
      LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o,
           LDAPConnectionDetailsJSONSpecification.FIELD_CONNECTION_OPTIONS,
           FIELD_CONNECT_TIMEOUT_MILLIS,
           FIELD_DEFAULT_RESPONSE_TIMEOUT_MILLIS,
           FIELD_FOLLOW_REFERRALS,
           FIELD_USE_SCHEMA,
           FIELD_USE_SYNCHRONOUS_MODE);

      referrals = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_FOLLOW_REFERRALS, referrals);

      schema = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_USE_SCHEMA, schema);

      synchronous = LDAPConnectionDetailsJSONSpecification.getBoolean(o,
           FIELD_USE_SYNCHRONOUS_MODE, synchronous);

      connect = LDAPConnectionDetailsJSONSpecification.getInt(o,
           FIELD_CONNECT_TIMEOUT_MILLIS, connect, 0, null);

      response = LDAPConnectionDetailsJSONSpecification.getLong(o,
           FIELD_DEFAULT_RESPONSE_TIMEOUT_MILLIS, response, 0L, null);
    }

    followReferrals              = referrals;
    useSchema                    = schema;
    useSynchronousMode           = synchronous;
    connectTimeoutMillis         = connect;
    defaultResponseTimeoutMillis = response;
  }



  /**
   * Creates an {@link LDAPConnectionOptions} object from the information in
   * the provided specification.
   *
   * @param  securityOptions  The security options created from the JSON
   *                          specification.
   *
   * @return  The {@code LDAPConnectionOptions} object that was created.
   */
  @NotNull()
  LDAPConnectionOptions createConnectionOptions(
                             @NotNull final SecurityOptions securityOptions)
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();

    options.setFollowReferrals(followReferrals);
    options.setUseSchema(useSchema);
    options.setUseSynchronousMode(useSynchronousMode);
    options.setConnectTimeoutMillis(connectTimeoutMillis);
    options.setResponseTimeoutMillis(defaultResponseTimeoutMillis);

    if (securityOptions.verifyAddressInCertificate())
    {
      options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
    }

    return options;
  }
}
