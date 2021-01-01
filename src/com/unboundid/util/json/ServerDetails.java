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



import java.util.ArrayList;
import java.util.List;
import javax.net.SocketFactory;

import com.unboundid.ldap.sdk.FailoverServerSet;
import com.unboundid.ldap.sdk.FastestConnectServerSet;
import com.unboundid.ldap.sdk.FewestConnectionsServerSet;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a data structure and set of logic for interacting with
 * the set of server details in a JSON object provided to the
 * {@link LDAPConnectionDetailsJSONSpecification}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class ServerDetails
{
  /**
   * The name of the field that provides the address of a directory server
   * instance.  Its value must be a string.
   */
  @NotNull private static final String FIELD_ADDRESS = "address";



  /**
   * The name of the field that may be used to provide the failover order for
   * use in conjunction with a failover server set.  Its value must be an array
   * of JSON objects, where each of those objects must have one field, which
   * should be one of the following types:  failover-set, fastest-connect-set,
   * fewest-connections-set, round-robin-set, or single-server.
   */
  @NotNull private static final String FIELD_FAILOVER_ORDER = "failover-order";



  /**
   * The name of the field that may be used to provide information about a set
   * of servers that should be accessed in a manner that selects servers in a
   * consistent failover manner.  Its value must be a JSON object that must
   * contain the failover-order field and may optionally contain the
   * maximum-failover-connection-age-millis and  re-order-on-failover fields.
   */
  @NotNull private static final String FIELD_FAILOVER_SET = "failover-set";



  /**
   * The name of the field that may be used to provide information about a set
   * of servers that should be accessed in a manner that selects the server that
   * accepts a connection first.  Its value must be a JSON object that must
   * contain only the servers field.
   */
  @NotNull private static final String FIELD_FASTEST_CONNECT_SET =
       "fastest-connect-set";



  /**
   * The name of the field that may be used to provide information about a set
   * of servers that should be accessed in a manner that selects the server with
   * the fewest active connections.  Its value must be a JSON object that must
   * contain only the servers field.
   */
  @NotNull private static final String FIELD_FEWEST_CONNECTIONS_SET =
       "fewest-connections-set";



  /**
   * The name of the field that may be used to specify the maximum connection
   * age (in milliseconds) that should be used for connections created by a
   * failover server set when the connection cannot be established to the
   * first-choice server.  If present, its value must be an integer value that
   * is greater than or equal to zero (with a value of zero indicating that no
   * maximum age should be enforced for such connections.  If it is not present,
   * then these connections will be given the associated connection pool's
   * maximum connection age.
   */
  @NotNull private static final String FIELD_MAX_FAILOVER_CONN_AGE_MILLIS =
       "maximum-failover-connection-age-millis";



  /**
   * The name of the field that provides the port of a directory server
   * instance.  Its value must be an integer between 1 and 65535.
   */
  @NotNull private static final String FIELD_PORT = "port";



  /**
   * The name of the field that may be used to provide information about a set
   * of servers that should be accessed in a round-robin fashion.  Its value
   * must be a JSON object that must contain only the servers field.
   */
  @NotNull private static final String FIELD_ROUND_ROBIN_SET =
       "round-robin-set";



  /**
   * The name of the field that may be used to provide information about a
   * set of servers to include in a set.  Its value must be an array of one or
   * more JSON objects, in which each object must contain only the address and
   * port fields.
   */
  @NotNull private static final String FIELD_SERVERS = "servers";



  /**
   * The name of the field that may be used to provide information about a
   * single directory server instance.  Its value must be a JSON object that
   * must contain only the address and port fields.
   */
  @NotNull private static final String FIELD_SINGLE_SERVER = "single-server";



  // The server set created from the server details specification.
  @NotNull private final ServerSet serverSet;



  /**
   * Creates a new set of connection options from the information contained in
   * the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object containing the LDAP
   *                                  connection details specification.
   * @param  securityOptions          The parsed security options portion of the
   *                                  specification.
   * @param  connectionOptions        The parsed connection options portion of
   *                                  the specification.
   *
   * @throws  LDAPException  If there is a problem with the server details data
   *                         in the provided JSON object.
   */
  ServerDetails(@NotNull final JSONObject connectionDetailsObject,
                @NotNull final SecurityOptions securityOptions,
                @NotNull final ConnectionOptions connectionOptions)
       throws LDAPException
  {
    final JSONObject o = LDAPConnectionDetailsJSONSpecification.getObject(
         connectionDetailsObject,
         LDAPConnectionDetailsJSONSpecification.FIELD_SERVER_DETAILS);

    serverSet = createServerSet(o,
         LDAPConnectionDetailsJSONSpecification.FIELD_SERVER_DETAILS,
         securityOptions, connectionOptions);
  }



  /**
   * Creates a server set from the information contained in the provided JSON
   * object.
   *
   * @param  o                  The JSON object to parse as a server set.
   * @param  fieldName          The name of the field whose value contains the
   *                            provided JSON object.
   * @param  securityOptions    The parsed security options portion of the
   *                            specification.
   * @param  connectionOptions  The parsed connection options portion of the
   *                            specification.
   *
   * @return  The server set created from the information in the provided JSON
   *          object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed to
   *                         create a server set.
   */
  @NotNull()
  private static ServerSet createServerSet(@NotNull final JSONObject o,
                      @NotNull final String fieldName,
                      @NotNull final SecurityOptions securityOptions,
                      @NotNull final ConnectionOptions connectionOptions)
          throws LDAPException
  {
    LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o, fieldName,
         FIELD_FAILOVER_SET,
         FIELD_FASTEST_CONNECT_SET,
         FIELD_FEWEST_CONNECTIONS_SET,
         FIELD_ROUND_ROBIN_SET,
         FIELD_SINGLE_SERVER);

    final SocketFactory socketFactory = securityOptions.getSocketFactory();
    final LDAPConnectionOptions ldapConnectionOptions =
         connectionOptions.createConnectionOptions(securityOptions);

    if (o.getFields().size() != 1)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_INVALID_FIELD_SET.get(fieldName));
    }


    // See if it's a failover set definition.
    final JSONObject failoverSetObject =
         LDAPConnectionDetailsJSONSpecification.getObject(o,
              FIELD_FAILOVER_SET);
    if (failoverSetObject != null)
    {
      LDAPConnectionDetailsJSONSpecification.validateAllowedFields(
           failoverSetObject, FIELD_FAILOVER_SET,
           FIELD_FAILOVER_ORDER,
           FIELD_MAX_FAILOVER_CONN_AGE_MILLIS);

      final Long maxFailoverConnectionAgeMillis =
           LDAPConnectionDetailsJSONSpecification.getLong(failoverSetObject,
                FIELD_MAX_FAILOVER_CONN_AGE_MILLIS, null, 0L, null);

      final JSONValue orderValue =
           failoverSetObject.getField(FIELD_FAILOVER_ORDER);
      if (orderValue == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SERVER_DETAILS_MISSING_FIELD.get(FIELD_FAILOVER_SET,
                  FIELD_FAILOVER_ORDER));
      }

      if (! (orderValue instanceof JSONArray))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SERVER_DETAILS_FIELD_NOT_ARRAY.get(FIELD_FAILOVER_SET,
                  FIELD_FAILOVER_ORDER));
      }

      final JSONArray orderArray = (JSONArray) orderValue;
      final List<JSONValue> orderArrayValues = orderArray.getValues();
      if (orderArrayValues.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SERVER_DETAILS_EMPTY_ARRAY.get(FIELD_FAILOVER_SET,
                  FIELD_FAILOVER_ORDER));
      }

      final ArrayList<ServerSet> failoverSets =
           new ArrayList<>(orderArrayValues.size());
      for (final JSONValue v : orderArrayValues)
      {
        if (! (v instanceof JSONObject))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SERVER_DETAILS_SERVERS_VALUE_NOT_OBJECT.get(
                    FIELD_FAILOVER_ORDER, FIELD_FAILOVER_SET));
        }

        failoverSets.add(createServerSet((JSONObject) v, FIELD_FAILOVER_ORDER,
             securityOptions, connectionOptions));
      }

      final FailoverServerSet failoverSet = new FailoverServerSet(failoverSets);
      failoverSet.setMaxFailoverConnectionAgeMillis(
           maxFailoverConnectionAgeMillis);
      return failoverSet;
    }


    // See if it's a fastest connect set definition.
    final JSONObject fastestConnectSetObject =
         LDAPConnectionDetailsJSONSpecification.getObject(o,
              FIELD_FASTEST_CONNECT_SET);
    if (fastestConnectSetObject != null)
    {
      final ObjectPair<String[],int[]> servers =
           parseServers(fastestConnectSetObject, FIELD_SERVERS);
      return new FastestConnectServerSet(servers.getFirst(),
           servers.getSecond(), socketFactory, ldapConnectionOptions);
    }


    // See if it's a fewest connections set definition.
    final JSONObject fewestConnectionsSetObject =
         LDAPConnectionDetailsJSONSpecification.getObject(o,
              FIELD_FEWEST_CONNECTIONS_SET);
    if (fewestConnectionsSetObject != null)
    {
      final ObjectPair<String[],int[]> servers =
           parseServers(fewestConnectionsSetObject, FIELD_SERVERS);
      return new FewestConnectionsServerSet(servers.getFirst(),
           servers.getSecond(), socketFactory, ldapConnectionOptions);
    }


    // See if it's a round-robin set definition.
    final JSONObject roundRobinSetObject =
         LDAPConnectionDetailsJSONSpecification.getObject(o,
              FIELD_ROUND_ROBIN_SET);
    if (roundRobinSetObject != null)
    {
      final ObjectPair<String[],int[]> servers =
           parseServers(roundRobinSetObject, FIELD_SERVERS);
      return new RoundRobinServerSet(servers.getFirst(),
           servers.getSecond(), socketFactory, ldapConnectionOptions);
    }


    // It must be a single server definition.
    final JSONObject singleServerObject =
         LDAPConnectionDetailsJSONSpecification.getObject(o,
              FIELD_SINGLE_SERVER);
    final ObjectPair<String,Integer> addressAndPort = parseServer(
         singleServerObject, FIELD_SINGLE_SERVER);
    return new SingleServerSet(addressAndPort.getFirst(),
         addressAndPort.getSecond(), socketFactory, ldapConnectionOptions);
  }



  /**
   * Parses information about a set of servers from the information contained
   * in the provided JSON object.
   *
   * @param  o  The JSON object to parse.
   * @param  f  The name of the field in which the provided object is a value.
   *
   * @return  An object pair containing the addresses and ports of the servers.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed to
   *                         obtain information about a set of servers.
   */
  @NotNull()
  private static ObjectPair<String[],int[]> parseServers(
                                                 @NotNull final JSONObject o,
                                                 @NotNull final String f)
          throws LDAPException
  {
    LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o, f,
         FIELD_SERVERS);

    final JSONValue serversValue = o.getField(FIELD_SERVERS);
    if (serversValue == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_MISSING_FIELD.get(f, FIELD_SERVERS));
    }

    if (! (serversValue instanceof JSONArray))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_FIELD_NOT_ARRAY.get(f, FIELD_SERVERS));
    }

    final List<JSONValue> serverArrayValues =
         ((JSONArray) serversValue).getValues();
    if (serverArrayValues.isEmpty())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_EMPTY_ARRAY.get(f, FIELD_SERVERS));
    }

    int i=0;
    final String[] addresses = new String[serverArrayValues.size()];
    final int[] ports        = new int[addresses.length];
    for (final JSONValue v : serverArrayValues)
    {
      if (! (v instanceof JSONObject))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SERVER_DETAILS_SERVERS_VALUE_NOT_OBJECT.get(FIELD_SERVERS, f));
      }

      final ObjectPair<String,Integer> p = parseServer((JSONObject) v,
           FIELD_SERVERS);
      addresses[i] = p.getFirst();
      ports[i] = p.getSecond();

      i++;
    }

    return new ObjectPair<>(addresses, ports);
  }



  /**
   * Parses information about a single server from the information contained in
   * the provided JSON object.
   *
   * @param  o  The JSON object to parse.
   * @param  f  The name of the field in which the provided object is a value.
   *
   * @return  An object pair containing the address and port for the server.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed to
   *                         obtain information about a server.
   */
  @NotNull()
  private static ObjectPair<String,Integer> parseServer(
                                                 @NotNull final JSONObject o,
                                                 @NotNull final String f)
          throws LDAPException
  {
    LDAPConnectionDetailsJSONSpecification.validateAllowedFields(o, f,
         FIELD_ADDRESS,
         FIELD_PORT);

    final String address = LDAPConnectionDetailsJSONSpecification.getString(o,
         FIELD_ADDRESS, null);
    if (address == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_MISSING_FIELD.get(f, FIELD_ADDRESS));
    }

    final Integer port = LDAPConnectionDetailsJSONSpecification.getInt(o,
         FIELD_PORT, null, 1, 65_535);
    if (port == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SERVER_DETAILS_MISSING_FIELD.get(f, FIELD_PORT));
    }

    return new ObjectPair<>(address, port);
  }



  /**
   * Retrieves the server set.
   *
   * @return  The server set.
   */
  @NotNull()
  ServerSet getServerSet()
  {
    return serverSet;
  }
}
