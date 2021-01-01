/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import javax.naming.Context;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a server set implementation that can discover information
 * about available directory servers through DNS SRV records as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2782.txt">RFC 2782</A>.  DNS SRV records
 * make it possible for clients to use the domain name system to discover
 * information about the systems that provide a given service, which can help
 * avoid the need to explicitly configure clients with the addresses of the
 * appropriate set of directory servers.
 * <BR><BR>
 * The standard service name used to reference LDAP directory servers is
 * "_ldap._tcp".  If client systems have DNS configured properly with an
 * appropriate search domain, then this may be all that is needed to discover
 * any available directory servers.  Alternately, a record name of
 * "_ldap._tcp.example.com" may be used to request DNS information about LDAP
 * servers for the example.com domain.  However, there is no technical
 * requirement that "_ldap._tcp" must be used for this purpose, and it may make
 * sense to use a different name if there is something special about the way
 * clients should interact with the servers (e.g., "_ldaps._tcp" would be more
 * appropriate if LDAP clients need to use SSL when communicating with the
 * server).
 * <BR><BR>
 * DNS SRV records contain a number of components, including:
 * <UL>
 *   <LI>The address of the system providing the service.</LI>
 *   <LI>The port to which connections should be established to access the
 *       service.</LI>
 *   <LI>The priority assigned to the service record.  If there are multiple
 *       servers that provide the associated service, then the priority can be
 *       used to specify the order in which they should be contacted.  Records
 *       with a lower priority value wil be used before those with a higher
 *       priority value.</LI>
 *   <LI>The weight assigned to the service record.  The weight will be used if
 *       there are multiple service records with the same priority, and it
 *       controls how likely each record is to be chosen.  A record with a
 *       weight of 2 is twice as likely to be chosen as a record with the same
 *       priority and a weight of 1.</LI>
 * </UL>
 * In the event that multiple SRV records exist for the target service, then the
 * priorities and weights of those records will be used to determine the order
 * in which the servers will be tried.  Records with a lower priority value will
 * always be tried before those with a higher priority value.  For records with
 * equal priority values and nonzero weights, then the ratio of those weight
 * values will be used to control how likely one of those records is to be tried
 * before another.  Records with a weight of zero will always be tried after
 * records with the same priority and nonzero weights.
 * <BR><BR>
 * This server set implementation uses JNDI to communicate with DNS servers in
 * order to obtain the requested SRV records (although it does not use JNDI for
 * any LDAP communication).  In order to specify which DNS server(s) to query, a
 * JNDI provider URL must be used.  In many cases, a URL of "dns:", which
 * indicates that the client should use the DNS servers configured for use by
 * the underlying system, should be sufficient.  However, if you wish to use a
 * specific DNS server then you may explicitly specify it in the URL (e.g.,
 * "dns://1.2.3.4:53" would attempt to communicate with the DNS server listening
 * on IP address 1.2.3.4 and port 53).  If you wish to specify multiple DNS
 * servers, you may provide multiple URLs separated with spaces and they will be
 * tried in the order in which they were included in the list until a response
 * can be retrieved (e.g., for a provider URL of "dns://1.2.3.4 dns://1.2.3.5",
 * it will first try to use the DNS server running on system with IP address
 * "1.2.3.4", but if that is not successful then it will try the DNS server
 * running on the system with IP address "1.2.3.5").  See the <A HREF=
 *"http://download.oracle.com/javase/6/docs/technotes/guides/jndi/jndi-dns.html"
 * > JNDI DNS service provider documentation</A> for more details on acceptable
 * formats for the provider URL.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNSSRVRecordServerSet
       extends ServerSet
{
  /**
   * The default SRV record name that will be retrieved if none is specified.
   */
  @NotNull private static final String DEFAULT_RECORD_NAME = "_ldap._tcp";



  /**
   * The default time-to-live value (1 hour, represented in milliseconds) that
   * will be used if no alternate value is specified.
   */
  private static final long DEFAULT_TTL_MILLIS = 60L * 60L * 1000L;



  /**
   * The default provider URL that will be used for specifying which DNS
   * server(s) to query.  The default behavior will be to attempt to determine
   * which DNS server(s) to use from the underlying system configuration.
   */
  @NotNull private static final String DEFAULT_DNS_PROVIDER_URL = "dns:";



  // The bind request to use to authenticate connections created by this
  // server set.
  @Nullable private final BindRequest bindRequest;

  // The properties that will be used to initialize the JNDI context.
  @NotNull private final Hashtable<String,String> jndiProperties;

  // The connection options to use for newly-created connections.
  @Nullable private final LDAPConnectionOptions connectionOptions;

  // The maximum length of time in milliseconds that previously-retrieved
  // information should be considered valid.
  private final long ttlMillis;

  // The post-connect processor to invoke against connections created by this
  // server set.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The socket factory that should be used to create connections.
  @Nullable private final SocketFactory socketFactory;

  // The cached set of SRV records.
  @Nullable private volatile SRVRecordSet recordSet;

  // The name of the DNS SRV record to retrieve.
  @NotNull private final String recordName;

  // The DNS provider URL to use.
  @NotNull private final String providerURL;



  /**
   * Creates a new instance of this server set that will use the specified DNS
   * record name, a default DNS provider URL that will attempt to determine DNS
   * servers from the underlying system configuration, a default TTL of one
   * hour, round-robin ordering for servers with the same priority, and default
   * socket factory and connection options.
   *
   * @param  recordName  The name of the DNS SRV record to retrieve.  If this is
   *                     {@code null}, then a default record name of
   *                     "_ldap._tcp" will be used.
   */
  public DNSSRVRecordServerSet(@Nullable final String recordName)
  {
    this(recordName, null, DEFAULT_TTL_MILLIS, null, null);
  }



  /**
   * Creates a new instance of this server set that will use the provided
   * settings.
   *
   * @param  recordName         The name of the DNS SRV record to retrieve.  If
   *                            this is {@code null}, then a default record name
   *                            of "_ldap._tcp" will be used.
   * @param  providerURL        The JNDI provider URL that may be used to
   *                            specify the DNS server(s) to use.  If this is
   *                            not specified, then a default URL of "dns:" will
   *                            be used, which will attempt to determine the
   *                            appropriate servers from the underlying system
   *                            configuration.
   * @param  ttlMillis          Specifies the maximum length of time in
   *                            milliseconds that DNS information should be
   *                            cached before it needs to be retrieved again.  A
   *                            value less than or equal to zero will use the
   *                            default TTL of one hour.
   * @param  socketFactory      The socket factory that will be used when
   *                            creating connections.  It may be {@code null} if
   *                            the JVM-default socket factory should be used.
   * @param  connectionOptions  The set of connection options that should be
   *                            used for the connections that are created.  It
   *                            may be {@code null} if the default connection
   *                            options should be used.
   */
  public DNSSRVRecordServerSet(@Nullable final String recordName,
              @Nullable final String providerURL,
              final long ttlMillis,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(recordName, providerURL, null, ttlMillis, socketFactory,
         connectionOptions);
  }



  /**
   * Creates a new instance of this server set that will use the provided
   * settings.
   *
   * @param  recordName         The name of the DNS SRV record to retrieve.  If
   *                            this is {@code null}, then a default record name
   *                            of "_ldap._tcp" will be used.
   * @param  providerURL        The JNDI provider URL that may be used to
   *                            specify the DNS server(s) to use.  If this is
   *                            not specified, then a default URL of "dns:" will
   *                            be used, which will attempt to determine the
   *                            appropriate servers from the underlying system
   *                            configuration.
   * @param  jndiProperties     A set of JNDI-related properties that should be
   *                            be used when initializing the context for
   *                            interacting with the DNS server via JNDI.  If
   *                            this is {@code null}, then a default set of
   *                            properties will be used.
   * @param  ttlMillis          Specifies the maximum length of time in
   *                            milliseconds that DNS information should be
   *                            cached before it needs to be retrieved again.  A
   *                            value less than or equal to zero will use the
   *                            default TTL of one hour.
   * @param  socketFactory      The socket factory that will be used when
   *                            creating connections.  It may be {@code null} if
   *                            the JVM-default socket factory should be used.
   * @param  connectionOptions  The set of connection options that should be
   *                            used for the connections that are created.  It
   *                            may be {@code null} if the default connection
   *                            options should be used.
   */
  public DNSSRVRecordServerSet(@Nullable final String recordName,
              @Nullable final String providerURL,
              @Nullable final Properties jndiProperties,
              final long ttlMillis,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(recordName, providerURL, jndiProperties, ttlMillis, socketFactory,
         connectionOptions, null, null);
  }



  /**
   * Creates a new instance of this server set that will use the provided
   * settings.
   *
   * @param  recordName            The name of the DNS SRV record to retrieve.
   *                               If this is {@code null}, then a default
   *                               record name of "_ldap._tcp" will be used.
   * @param  providerURL           The JNDI provider URL that may be used to
   *                               specify the DNS server(s) to use.  If this is
   *                               not specified, then a default URL of
   *                               "dns:" will be used, which will attempt to
   *                               determine the appropriate servers from the
   *                               underlying system configuration.
   * @param  jndiProperties        A set of JNDI-related properties that should
   *                               be be used when initializing the context for
   *                               interacting with the DNS server via JNDI.
   *                               If this is {@code null}, then a default set
   *                               of properties will be used.
   * @param  ttlMillis             Specifies the maximum length of time in
   *                               milliseconds that DNS information should be
   *                               cached before it needs to be retrieved
   *                               again.  A value less than or equal to zero
   *                               will use the default TTL of one hour.
   * @param  socketFactory         The socket factory that will be used when
   *                               creating connections.  It may be
   *                               {@code null} if the JVM-default socket
   *                               factory should be used.
   * @param  connectionOptions     The set of connection options that should be
   *                               used for the connections that are created.
   *                               It may be {@code null} if the default
   *                               connection options should be used.
   * @param  bindRequest           The bind request that should be used to
   *                               authenticate newly-established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly-established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public DNSSRVRecordServerSet(@Nullable final String recordName,
              @Nullable final String providerURL,
              @Nullable final Properties jndiProperties,
              final long ttlMillis,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    this.socketFactory = socketFactory;
    this.connectionOptions = connectionOptions;
    this.bindRequest = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    recordSet = null;

    if (recordName == null)
    {
      this.recordName = DEFAULT_RECORD_NAME;
    }
    else
    {
      this.recordName = recordName;
    }

    if (providerURL == null)
    {
      this.providerURL = DEFAULT_DNS_PROVIDER_URL;
    }
    else
    {
      this.providerURL = providerURL;
    }

    this.jndiProperties = new Hashtable<>(10);
    if (jndiProperties != null)
    {
      for (final Map.Entry<Object,Object> e : jndiProperties.entrySet())
      {
        this.jndiProperties.put(String.valueOf(e.getKey()),
             String.valueOf(e.getValue()));
      }
    }

    if (! this.jndiProperties.containsKey(Context.INITIAL_CONTEXT_FACTORY))
    {
      this.jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY,
           "com.sun.jndi.dns.DnsContextFactory");
    }

    if (! this.jndiProperties.containsKey(Context.PROVIDER_URL))
    {
      this.jndiProperties.put(Context.PROVIDER_URL, this.providerURL);
    }

    if (ttlMillis <= 0L)
    {
      this.ttlMillis = DEFAULT_TTL_MILLIS;
    }
    else
    {
      this.ttlMillis = ttlMillis;
    }
  }



  /**
   * Retrieves the name of the DNS SRV record to retrieve.
   *
   * @return  The name of the DNS SRV record to retrieve.
   */
  @NotNull()
  public String getRecordName()
  {
    return recordName;
  }



  /**
   * Retrieves the JNDI provider URL that specifies the DNS server(s) to use.
   *
   * @return  The JNDI provider URL that specifies the DNS server(s) to use.
   */
  @NotNull()
  public String getProviderURL()
  {
    return providerURL;
  }



  /**
   * Retrieves an unmodifiable map of properties that will be used to initialize
   * the JNDI context used to interact with DNS.  Note that the map returned
   * will reflect the actual properties that will be used, and may not exactly
   * match the properties provided when creating this server set.
   *
   * @return  An unmodifiable map of properties that will be used to initialize
   *          the JNDI context used to interact with DNS.
   */
  @NotNull()
  public Map<String,String> getJNDIProperties()
  {
    return Collections.unmodifiableMap(jndiProperties);
  }



  /**
   * Retrieves the maximum length of time in milliseconds that
   * previously-retrieved DNS information should be cached before it needs to be
   * refreshed.
   *
   * @return  The maximum length of time in milliseconds that
   *          previously-retrieved DNS information should be cached before it
   *          needs to be refreshed.
   */
  public long getTTLMillis()
  {
    return ttlMillis;
  }



  /**
   * Retrieves the socket factory that will be used when creating connections,
   * if any.
   *
   * @return  The socket factory that will be used when creating connections, or
   *          {@code null} if the JVM-default socket factory will be used.
   */
  @Nullable()
  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Retrieves the set of connection options to use for connections that are
   * created, if any.
   *
   * @return  The set of connection options to use for connections that are
   *          created, or {@code null} if a default set of options should be
   *          used.
   */
  @Nullable()
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesAuthentication()
  {
    return (bindRequest != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean includesPostConnectProcessing()
  {
    return (postConnectProcessor != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getConnection(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    // If there is no cached record set, or if the cached set is expired, then
    // try to get a new one.
    if ((recordSet == null) || recordSet.isExpired())
    {
      try
      {
        recordSet = SRVRecordSet.getRecordSet(recordName, jndiProperties,
             ttlMillis);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        // We couldn't get a new record set.  If we have an existing one, then
        // it's expired but we'll keep using it anyway because it's better than
        // nothing.  But if we don't have an existing set, then we can't
        // continue.
        if (recordSet == null)
        {
          throw le;
        }
      }
    }


    // Iterate through the record set in an order based on priority and weight.
    // Take the first one that we can connect to and that satisfies the health
    // check (if any).
    LDAPException firstException = null;
    for (final SRVRecord r : recordSet.getOrderedRecords())
    {
      try
      {
        final LDAPConnection connection = new LDAPConnection(socketFactory,
             connectionOptions, r.getAddress(), r.getPort());
        doBindPostConnectAndHealthCheckProcessing(connection, bindRequest,
             postConnectProcessor, healthCheck);
        associateConnectionWithThisServerSet(connection);
        return connection;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        if (firstException == null)
        {
          firstException = le;
        }
      }
    }

    // If we've gotten here, then we couldn't connect to any of the servers.
    // Throw the first exception that we encountered.
    throw firstException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DNSSRVRecordServerSet(recordName='");
    buffer.append(recordName);
    buffer.append("', providerURL='");
    buffer.append(providerURL);
    buffer.append("', ttlMillis=");
    buffer.append(ttlMillis);

    if (socketFactory != null)
    {
      buffer.append(", socketFactoryClass='");
      buffer.append(socketFactory.getClass().getName());
      buffer.append('\'');
    }

    if (connectionOptions != null)
    {
      buffer.append(", connectionOptions");
      connectionOptions.toString(buffer);
    }

    buffer.append(", includesAuthentication=");
    buffer.append(bindRequest != null);
    buffer.append(", includesPostConnectProcessing=");
    buffer.append(postConnectProcessor != null);
    buffer.append(')');
  }
}
