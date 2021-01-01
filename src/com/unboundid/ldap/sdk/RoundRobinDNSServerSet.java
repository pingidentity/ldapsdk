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
package com.unboundid.ldap.sdk;



import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.net.SocketFactory;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadLocalRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a server set implementation that handles the case in
 * which a given host name may resolve to multiple IP addresses.  Note that
 * while a setup like this is typically referred to as "round-robin DNS", this
 * server set implementation does not strictly require DNS (as names may be
 * resolved through alternate mechanisms like a hosts file or an alternate name
 * service), and it does not strictly require round-robin use of those addresses
 * (as alternate ordering mechanisms, like randomized or failover, may be used).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a round-robin DNS
 * server set for the case in which the hostname "directory.example.com" may be
 * associated with multiple IP addresses, and the LDAP SDK should attempt to use
 * them in a round robin manner.
 * <PRE>
 *   // Define a number of variables that will be used by the server set.
 *   String                hostname           = "directory.example.com";
 *   int                   port               = 389;
 *   AddressSelectionMode  selectionMode      =
 *        AddressSelectionMode.ROUND_ROBIN;
 *   long                  cacheTimeoutMillis = 3600000L; // 1 hour
 *   String                providerURL        = "dns:"; // Default DNS config.
 *   SocketFactory         socketFactory      = null; // Default socket factory.
 *   LDAPConnectionOptions connectionOptions  = null; // Default options.
 *
 *   // Create the server set using the settings defined above.
 *   RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(hostname,
 *        port, selectionMode, cacheTimeoutMillis, providerURL, socketFactory,
 *        connectionOptions);
 *
 *   // Verify that we can establish a single connection using the server set.
 *   LDAPConnection connection = serverSet.getConnection();
 *   RootDSE rootDSEFromConnection = connection.getRootDSE();
 *   connection.close();
 *
 *   // Verify that we can establish a connection pool using the server set.
 *   SimpleBindRequest bindRequest =
 *        new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
 *   LDAPConnectionPool pool =
 *        new LDAPConnectionPool(serverSet, bindRequest, 10);
 *   RootDSE rootDSEFromPool = pool.getRootDSE();
 *   pool.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RoundRobinDNSServerSet
       extends ServerSet
{
  /**
   * The name of a system property that can be used to specify a comma-delimited
   * list of IP addresses to use if resolution fails.  This is intended
   * primarily for testing purposes.
   */
  @NotNull static final String PROPERTY_DEFAULT_ADDRESSES =
       RoundRobinDNSServerSet.class.getName() + ".defaultAddresses";



  /**
   * An enum that defines the modes that may be used to select the order in
   * which addresses should be used in attempts to establish connections.
   */
  public enum AddressSelectionMode
  {
    /**
     * The address selection mode that will cause addresses to be consistently
     * attempted in the order they are retrieved from the name service.
     */
    FAILOVER,



    /**
     * The address selection mode that will cause the order of addresses to be
     * randomized for each attempt.
     */
    RANDOM,



    /**
     * The address selection mode that will cause connection attempts to be made
     * in a round-robin order.
     */
    ROUND_ROBIN;



    /**
     * Retrieves the address selection mode with the specified name.
     *
     * @param  name  The name of the address selection mode to retrieve.  It
     *              must not be {@code null}.
     *
     * @return  The requested address selection mode, or {@code null} if no such
     *          change mode is defined.
     */
    @Nullable()
    public static AddressSelectionMode forName(@NotNull final String name)
    {
      switch (StaticUtils.toLowerCase(name))
      {
        case "failover":
          return FAILOVER;
        case "random":
          return RANDOM;
        case "roundrobin":
        case "round-robin":
        case "round_robin":
          return ROUND_ROBIN;
        default:
          return null;
      }
    }
  }



  // The address selection mode that should be used if the provided hostname
  // resolves to multiple addresses.
  @NotNull private final AddressSelectionMode selectionMode;

  // A counter that will be used to handle round-robin ordering.
  @NotNull private final AtomicLong roundRobinCounter;

  // A reference to an object that combines the resolved addresses with a
  // timestamp indicating when the value should no longer be trusted.
  @NotNull private final AtomicReference<ObjectPair<InetAddress[],Long>>
       resolvedAddressesWithTimeout;

  // The bind request to use to authenticate connections created by this
  // server set.
  @Nullable private final BindRequest bindRequest;

  // The properties that will be used to initialize the JNDI context, if any.
  @Nullable private final Hashtable<String,String> jndiProperties;

  // The port number for the target server.
  private final int port;

  // The set of connection options to use for new connections.
  @NotNull private final LDAPConnectionOptions connectionOptions;

  // The maximum length of time, in milliseconds, to cache resolved addresses.
  private final long cacheTimeoutMillis;

  // The post-connect processor to invoke against connections created by this
  // server set.
  @Nullable private final PostConnectProcessor postConnectProcessor;

  // The socket factory to use to establish connections.
  @NotNull private final SocketFactory socketFactory;

  // The hostname to be resolved.
  @NotNull private final String hostname;

  // The provider URL to use to resolve names, if any.
  @Nullable private final String providerURL;

  // The DNS record types that will be used to obtain the IP addresses for the
  // specified hostname.
  @NotNull private final String[] dnsRecordTypes;



  /**
   * Creates a new round-robin DNS server set with the provided information.
   *
   * @param  hostname            The hostname to be resolved to one or more
   *                             addresses.  It must not be {@code null}.
   * @param  port                The port to use to connect to the server.  Note
   *                             that even if the provided hostname resolves to
   *                             multiple addresses, the same port must be used
   *                             for all addresses.
   * @param  selectionMode       The selection mode that should be used if the
   *                             hostname resolves to multiple addresses.  It
   *                             must not be {@code null}.
   * @param  cacheTimeoutMillis  The maximum length of time in milliseconds to
   *                             cache addresses resolved from the provided
   *                             hostname.  Caching resolved addresses can
   *                             result in better performance and can reduce the
   *                             number of requests to the name service.  A
   *                             that is less than or equal to zero indicates
   *                             that no caching should be used.
   * @param  providerURL         The JNDI provider URL that should be used when
   *                             communicating with the DNS server.  If this is
   *                             {@code null}, then the underlying system's
   *                             name service mechanism will be used (which may
   *                             make use of other services instead of or in
   *                             addition to DNS).  If this is non-{@code null},
   *                             then only DNS will be used to perform the name
   *                             resolution.  A value of "dns:" indicates that
   *                             the underlying system's DNS configuration
   *                             should be used.
   * @param  socketFactory       The socket factory to use to establish the
   *                             connections.  It may be {@code null} if the
   *                             JVM-default socket factory should be used.
   * @param  connectionOptions   The set of connection options that should be
   *                             used for the connections.  It may be
   *                             {@code null} if a default set of connection
   *                             options should be used.
   */
  public RoundRobinDNSServerSet(@NotNull final String hostname, final int port,
              @NotNull final AddressSelectionMode selectionMode,
              final long cacheTimeoutMillis,
              @Nullable final String providerURL,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(hostname, port, selectionMode, cacheTimeoutMillis, providerURL,
         null, null, socketFactory, connectionOptions);
  }



  /**
   * Creates a new round-robin DNS server set with the provided information.
   *
   * @param  hostname            The hostname to be resolved to one or more
   *                             addresses.  It must not be {@code null}.
   * @param  port                The port to use to connect to the server.  Note
   *                             that even if the provided hostname resolves to
   *                             multiple addresses, the same port must be used
   *                             for all addresses.
   * @param  selectionMode       The selection mode that should be used if the
   *                             hostname resolves to multiple addresses.  It
   *                             must not be {@code null}.
   * @param  cacheTimeoutMillis  The maximum length of time in milliseconds to
   *                             cache addresses resolved from the provided
   *                             hostname.  Caching resolved addresses can
   *                             result in better performance and can reduce the
   *                             number of requests to the name service.  A
   *                             that is less than or equal to zero indicates
   *                             that no caching should be used.
   * @param  providerURL         The JNDI provider URL that should be used when
   *                             communicating with the DNS server.If both
   *                             {@code providerURL} and {@code jndiProperties}
   *                             are {@code null}, then then JNDI will not be
   *                             used to interact with DNS and the hostname
   *                             resolution will be performed via the underlying
   *                             system's name service mechanism (which may make
   *                             use of other services instead of or in addition
   *                             to DNS).  If this is non-{@code null}, then
   *                             only DNS will be used to perform the name
   *                             resolution.  A value of "dns:" indicates that
   *                             the underlying system's DNS configuration
   *                             should be used.
   * @param  jndiProperties      A set of JNDI-related properties that should be
   *                             be used when initializing the context for
   *                             interacting with the DNS server via JNDI.  If
   *                             both {@code providerURL} and
   *                             {@code jndiProperties} are {@code null}, then
   *                             then JNDI will not be used to interact with
   *                             DNS and the hostname resolution will be
   *                             performed via the underlying system's name
   *                             service mechanism (which may make use of other
   *                             services instead of or in addition to DNS).  If
   *                             {@code providerURL} is {@code null} and
   *                             {@code jndiProperties} is non-{@code null},
   *                             then the provided properties must specify the
   *                             URL.
   * @param  dnsRecordTypes      Specifies the types of DNS records that will be
   *                             used to obtain the addresses for the specified
   *                             hostname.  This will only be used if at least
   *                             one of {@code providerURL} and
   *                             {@code jndiProperties} is non-{@code null}.  If
   *                             this is {@code null} or empty, then a default
   *                             record type of "A" (indicating IPv4 addresses)
   *                             will be used.
   * @param  socketFactory       The socket factory to use to establish the
   *                             connections.  It may be {@code null} if the
   *                             JVM-default socket factory should be used.
   * @param  connectionOptions   The set of connection options that should be
   *                             used for the connections.  It may be
   *                             {@code null} if a default set of connection
   *                             options should be used.
   */
  public RoundRobinDNSServerSet(@NotNull final String hostname, final int port,
              @NotNull final AddressSelectionMode selectionMode,
              final long cacheTimeoutMillis,
              @Nullable final String providerURL,
              @Nullable final Properties jndiProperties,
              @Nullable final String[] dnsRecordTypes,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions)
  {
    this(hostname, port, selectionMode, cacheTimeoutMillis, providerURL,
         jndiProperties, dnsRecordTypes, socketFactory, connectionOptions, null,
         null);
  }



  /**
   * Creates a new round-robin DNS server set with the provided information.
   *
   * @param  hostname              The hostname to be resolved to one or more
   *                               addresses.  It must not be {@code null}.
   * @param  port                  The port to use to connect to the server.
   *                               Note that even if the provided hostname
   *                               resolves to multiple addresses, the same
   *                               port must be used for all addresses.
   * @param  selectionMode         The selection mode that should be used if the
   *                               hostname resolves to multiple addresses.  It
   *                               must not be {@code null}.
   * @param  cacheTimeoutMillis    The maximum length of time in milliseconds to
   *                               cache addresses resolved from the provided
   *                               hostname.  Caching resolved addresses can
   *                               result in better performance and can reduce
   *                               the number of requests to the name service.
   *                               A that is less than or equal to zero
   *                               indicates that no caching should be used.
   * @param  providerURL           The JNDI provider URL that should be used
   *                               when communicating with the DNS server.  If
   *                               both {@code providerURL} and
   *                               {@code jndiProperties} are {@code null},
   *                               then then JNDI will not be used to interact
   *                               with DNS and the hostname resolution will be
   *                               performed via the underlying system's name
   *                               service mechanism (which may make use of
   *                               other services instead of or in addition to
   *                               DNS).  If this is non-{@code null}, then only
   *                               DNS will be used to perform the name
   *                               resolution.  A value of "dns:" indicates that
   *                               the underlying system's DNS configuration
   *                               should be used.
   * @param  jndiProperties        A set of JNDI-related properties that should
   *                               be used when initializing the context for
   *                               interacting with the DNS server via JNDI.  If
   *                               both {@code providerURL} and
   *                               {@code jndiProperties} are {@code null}, then
   *                               JNDI will not be used to interact with DNS
   *                               and the hostname resolution will be
   *                               performed via the underlying system's name
   *                               service mechanism (which may make use of
   *                               other services instead of or in addition to
   *                               DNS).  If {@code providerURL} is
   *                               {@code null} and {@code jndiProperties} is
   *                               non-{@code null}, then the provided
   *                               properties must specify the URL.
   * @param  dnsRecordTypes        Specifies the types of DNS records that will
   *                               be used to obtain the addresses for the
   *                               specified hostname.  This will only be used
   *                               if at least one of {@code providerURL} and
   *                               {@code jndiProperties} is non-{@code null}.
   *                               If this is {@code null} or empty, then a
   *                               default record type of "A" (indicating IPv4
   *                               addresses) will be used.
   * @param  socketFactory         The socket factory to use to establish the
   *                               connections.  It may be {@code null} if the
   *                               JVM-default socket factory should be used.
   * @param  connectionOptions     The set of connection options that should be
   *                               used for the connections.  It may be
   *                               {@code null} if a default set of connection
   *                               options should be used.
   * @param  bindRequest           The bind request that should be used to
   *                               authenticate newly-established connections.
   *                               It may be {@code null} if this server set
   *                               should not perform any authentication.
   * @param  postConnectProcessor  The post-connect processor that should be
   *                               invoked on newly-established connections.  It
   *                               may be {@code null} if this server set should
   *                               not perform any post-connect processing.
   */
  public RoundRobinDNSServerSet(@NotNull final String hostname, final int port,
              @NotNull final AddressSelectionMode selectionMode,
              final long cacheTimeoutMillis,
              @Nullable final String providerURL,
              @Nullable final Properties jndiProperties,
              @Nullable final String[] dnsRecordTypes,
              @Nullable final SocketFactory socketFactory,
              @Nullable final LDAPConnectionOptions connectionOptions,
              @Nullable final BindRequest bindRequest,
              @Nullable final PostConnectProcessor postConnectProcessor)
  {
    Validator.ensureNotNull(hostname);
    Validator.ensureTrue((port >= 1) && (port <= 65_535));
    Validator.ensureNotNull(selectionMode);

    this.hostname = hostname;
    this.port = port;
    this.selectionMode = selectionMode;
    this.providerURL = providerURL;
    this.bindRequest = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    if (jndiProperties == null)
    {
      if (providerURL == null)
      {
        this.jndiProperties = null;
      }
      else
      {
        this.jndiProperties = new Hashtable<>(2);
        this.jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY,
             "com.sun.jndi.dns.DnsContextFactory");
        this.jndiProperties.put(Context.PROVIDER_URL, providerURL);
      }
    }
    else
    {
      this.jndiProperties = new Hashtable<>(jndiProperties.size()+2);
      for (final Map.Entry<Object,Object> e : jndiProperties.entrySet())
      {
        this.jndiProperties.put(String.valueOf(e.getKey()),
             String.valueOf(e.getValue()));
      }

      if (! this.jndiProperties.containsKey(Context.INITIAL_CONTEXT_FACTORY))
      {
        this.jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY,
             "com.sun.jndi.dns.DnsContextFactory");
      }

      if ((! this.jndiProperties.containsKey(Context.PROVIDER_URL)) &&
         (providerURL != null))
      {
        this.jndiProperties.put(Context.PROVIDER_URL, providerURL);
      }
    }

    if (dnsRecordTypes == null)
    {
      this.dnsRecordTypes = new String[] { "A" };
    }
    else
    {
      this.dnsRecordTypes = dnsRecordTypes;
    }

    if (cacheTimeoutMillis > 0L)
    {
      this.cacheTimeoutMillis = cacheTimeoutMillis;
    }
    else
    {
      this.cacheTimeoutMillis = 0L;
    }

    if (socketFactory == null)
    {
      this.socketFactory = SocketFactory.getDefault();
    }
    else
    {
      this.socketFactory = socketFactory;
    }

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions;
    }

    roundRobinCounter = new AtomicLong(0L);
    resolvedAddressesWithTimeout = new AtomicReference<>();
  }



  /**
   * Retrieves the hostname to be resolved.
   *
   * @return  The hostname to be resolved.
   */
  @NotNull()
  public String getHostname()
  {
    return hostname;
  }



  /**
   * Retrieves the port to use to connect to the server.
   *
   * @return  The port to use to connect to the server.
   */
  public int getPort()
  {
    return port;
  }



  /**
   * Retrieves the address selection mode that should be used if the provided
   * hostname resolves to multiple addresses.
   *
   * @return  The address selection
   */
  @NotNull()
  public AddressSelectionMode getAddressSelectionMode()
  {
    return selectionMode;
  }



  /**
   * Retrieves the length of time in milliseconds that resolved addresses may be
   * cached.
   *
   * @return  The length of time in milliseconds that resolved addresses may be
   *          cached, or zero if no caching should be performed.
   */
  public long getCacheTimeoutMillis()
  {
    return cacheTimeoutMillis;
  }



  /**
   * Retrieves the provider URL that should be used when interacting with DNS to
   * resolve the hostname to its corresponding addresses.
   *
   * @return  The provider URL that should be used when interacting with DNS to
   *          resolve the hostname to its corresponding addresses, or
   *          {@code null} if the system's configured naming service should be
   *          used.
   */
  @Nullable()
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
   *          the JNDI context used to interact with DNS, or {@code null} if
   *          JNDI will nto be used to interact with DNS.
   */
  @Nullable()
  public Map<String,String> getJNDIProperties()
  {
    if (jndiProperties == null)
    {
      return null;
    }
    else
    {
      return Collections.unmodifiableMap(jndiProperties);
    }
  }



  /**
   * Retrieves an array of record types that will be requested if JNDI will be
   * used to interact with DNS.
   *
   * @return  An array of record types that will be requested if JNDI will be
   *          used to interact with DNS.
   */
  @NotNull()
  public String[] getDNSRecordTypes()
  {
    return dnsRecordTypes;
  }



  /**
   * Retrieves the socket factory that will be used to establish connections.
   * This will not be {@code null}, even if no socket factory was provided when
   * the server set was created.
   *
   * @return  The socket factory that will be used to establish connections.
   */
  @NotNull()
  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Retrieves the set of connection options that will be used for underlying
   * connections.  This will not be {@code null}, even if no connection options
   * object was provided when the server set was created.
   *
   * @return  The set of connection options that will be used for underlying
   *          connections.
   */
  @NotNull()
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
  public synchronized LDAPConnection getConnection(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    LDAPException firstException = null;

    final LDAPConnection conn =
         new LDAPConnection(socketFactory, connectionOptions);
    for (final InetAddress a : orderAddresses(resolveHostname()))
    {
      boolean close = true;
      try
      {
        conn.connect(hostname, a, port,
             connectionOptions.getConnectTimeoutMillis());
        doBindPostConnectAndHealthCheckProcessing(conn, bindRequest,
             postConnectProcessor, healthCheck);
        close = false;
        associateConnectionWithThisServerSet(conn);
        return conn;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        if (firstException == null)
        {
          firstException = le;
        }
      }
      finally
      {
        if (close)
        {
          conn.close();
        }
      }
    }

    throw firstException;
  }



  /**
   * Resolve the hostname to its corresponding addresses.
   *
   * @return  The addresses resolved from the hostname.
   *
   * @throws  LDAPException  If
   */
  @NotNull()
  InetAddress[] resolveHostname()
          throws LDAPException
  {
    // First, see if we can use the cached addresses.
    final ObjectPair<InetAddress[],Long> pair =
         resolvedAddressesWithTimeout.get();
    if (pair != null)
    {
      if (pair.getSecond() >= System.currentTimeMillis())
      {
        return pair.getFirst();
      }
    }


    // Try to resolve the address.
    InetAddress[] addresses = null;
    try
    {
      if (jndiProperties == null)
      {
        addresses = connectionOptions.getNameResolver().getAllByName(hostname);
      }
      else
      {
        final Attributes attributes;
        final InitialDirContext context = new InitialDirContext(jndiProperties);
        try
        {
          attributes = context.getAttributes(hostname, dnsRecordTypes);
        }
        finally
        {
          context.close();
        }

        if (attributes != null)
        {
          final ArrayList<InetAddress> addressList = new ArrayList<>(10);
          for (final String recordType : dnsRecordTypes)
          {
            final Attribute a = attributes.get(recordType);
            if (a != null)
            {
              final NamingEnumeration<?> values = a.getAll();
              while (values.hasMore())
              {
                final Object value = values.next();
                addressList.add(getInetAddressForIP(String.valueOf(value)));
              }
            }
          }

          if (! addressList.isEmpty())
          {
            addresses = new InetAddress[addressList.size()];
            addressList.toArray(addresses);
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      addresses = getDefaultAddresses();
    }


    // If we were able to resolve the hostname, then cache and return the
    // resolved addresses.
    if ((addresses != null) && (addresses.length > 0))
    {
      final long timeoutTime;
      if (cacheTimeoutMillis > 0L)
      {
        timeoutTime = System.currentTimeMillis() + cacheTimeoutMillis;
      }
      else
      {
        timeoutTime = System.currentTimeMillis() - 1L;
      }

      resolvedAddressesWithTimeout.set(
           new ObjectPair<>(addresses, timeoutTime));
      return addresses;
    }


    // If we've gotten here, then we couldn't resolve the hostname.  If we have
    // cached addresses, then use them even though the timeout has expired
    // because that's better than nothing.
    if (pair != null)
    {
      return pair.getFirst();
    }

    throw new LDAPException(ResultCode.CONNECT_ERROR,
         ERR_ROUND_ROBIN_DNS_SERVER_SET_CANNOT_RESOLVE.get(hostname));
  }



  /**
   * Orders the provided array of InetAddress objects to reflect the order in
   * which the addresses should be used to try to create a new connection.
   *
   * @param  addresses  The array of addresses to be ordered.
   *
   * @return  A list containing the ordered addresses.
   */
  @NotNull()
  List<InetAddress> orderAddresses(@NotNull final InetAddress[] addresses)
  {
    final ArrayList<InetAddress> l = new ArrayList<>(addresses.length);

    switch (selectionMode)
    {
      case RANDOM:
        l.addAll(Arrays.asList(addresses));
        Collections.shuffle(l, ThreadLocalRandom.get());
        break;

      case ROUND_ROBIN:
        final int index =
             (int) (roundRobinCounter.getAndIncrement() % addresses.length);
        for (int i=index; i < addresses.length; i++)
        {
          l.add(addresses[i]);
        }
        for (int i=0; i < index; i++)
        {
          l.add(addresses[i]);
        }
        break;

      case FAILOVER:
      default:
        // We'll use the addresses in the same order we originally got them.
        l.addAll(Arrays.asList(addresses));
        break;
    }

    return l;
  }



  /**
   * Retrieves a default set of addresses that may be used for testing.
   *
   * @return  A default set of addresses that may be used for testing.
   */
  @NotNull()
  InetAddress[] getDefaultAddresses()
  {
    final String defaultAddrsStr =
         StaticUtils.getSystemProperty(PROPERTY_DEFAULT_ADDRESSES);
    if (defaultAddrsStr == null)
    {
      return null;
    }

    final StringTokenizer tokenizer =
         new StringTokenizer(defaultAddrsStr, " ,");
    final InetAddress[] addresses = new InetAddress[tokenizer.countTokens()];
    for (int i=0; i < addresses.length; i++)
    {
      try
      {
        addresses[i] = getInetAddressForIP(tokenizer.nextToken());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return null;
      }
    }

    return addresses;
  }



  /**
   * Retrieves an InetAddress object with the configured hostname and the
   * provided IP address.
   *
   * @param  ipAddress  The string representation of the IP address to use in
   *                    the returned InetAddress.
   *
   * @return  The created InetAddress.
   *
   * @throws  UnknownHostException  If the provided string does not represent a
   *                                valid IPv4 or IPv6 address.
   */
  @NotNull()
  private InetAddress getInetAddressForIP(@NotNull final String ipAddress)
          throws UnknownHostException
  {
    // We want to create an InetAddress that has the provided hostname and the
    // specified IP address.  To do that, we need to use
    // InetAddress.getByAddress.  But that requires the IP address to be
    // specified as a byte array, and the easiest way to convert an IP address
    // string to a byte array is to use InetAddress.getByName.
    final InetAddress byName = connectionOptions.getNameResolver().
         getByName(String.valueOf(ipAddress));
    return InetAddress.getByAddress(hostname, byName.getAddress());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RoundRobinDNSServerSet(hostname='");
    buffer.append(hostname);
    buffer.append("', port=");
    buffer.append(port);
    buffer.append(", addressSelectionMode=");
    buffer.append(selectionMode.name());
    buffer.append(", cacheTimeoutMillis=");
    buffer.append(cacheTimeoutMillis);

    if (providerURL != null)
    {
      buffer.append(", providerURL='");
      buffer.append(providerURL);
      buffer.append('\'');
    }

    buffer.append(", includesAuthentication=");
    buffer.append(bindRequest != null);
    buffer.append(", includesPostConnectProcessing=");
    buffer.append(postConnectProcessor != null);
    buffer.append(')');
  }
}
