/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadLocalRandom;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a {@code NameResolver} that will
 * cache lookups to potentially improve performance and provide a degree of
 * resiliency against name service outages.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CachingNameResolver
       extends NameResolver
{
  /**
   * The default timeout that will be used if none is specified.
   */
  private static final int DEFAULT_TIMEOUT_MILLIS = 3_600_000; // 1 hour



  // A cached version of the address of the local host system.
  @NotNull private final AtomicReference<ObjectPair<Long,InetAddress>>
       localHostAddress;

  // A cached version of the loopback address.
  @NotNull private final AtomicReference<ObjectPair<Long,InetAddress>>
       loopbackAddress;

  // A map that associates IP addresses with their canonical host names.  The
  // key will be the IP address, and the value will be an object pair that
  // associates the time that the cache record expires with the cached canonical
  // host name for the IP address.
  @NotNull private final Map<InetAddress,ObjectPair<Long,String>>
       addressToNameMap;

  // A map that associates host names with the set of all associated IP
  // addresses.  The key will be an all-lowercase representation of the host
  // name, and the value will be an object pair that associates the time that
  // the cache record expires with the cached set of IP addresses for the host
  // name.
  @NotNull private final Map<String,ObjectPair<Long,InetAddress[]>>
       nameToAddressMap;

  // The length of time, in milliseconds, that a cached record should be
  // considered valid.
  private final long timeoutMillis;



  /**
   * Creates a new instance of this caching name resolver that will use a
   * default timeout.
   */
  public CachingNameResolver()
  {
    this(DEFAULT_TIMEOUT_MILLIS);
  }



  /**
   * Creates a new instance of this caching name resolver that will use the
   * specified timeout.
   *
   * @param  timeoutMillis  The length of time, in milliseconds, that cache
   *                        records should be considered valid.  It must be
   *                        greater than zero.  If a record has been in the
   *                        cache for less than this period of time, then the
   *                        cached record will be used instead of making a name
   *                        service call.  If a record has been in the cache
   *                        for longer than this period of time, then the
   *                        cached record will only be used if it is not
   *                        possible to get an updated version of the record
   *                        from the name service.
   */
  public CachingNameResolver(final int timeoutMillis)
  {
    this.timeoutMillis = timeoutMillis;
    localHostAddress = new AtomicReference<>();
    loopbackAddress = new AtomicReference<>();
    addressToNameMap = new ConcurrentHashMap<>(20);
    nameToAddressMap = new ConcurrentHashMap<>(20);
  }



  /**
   * Retrieves the length of time, in milliseconds, that cache records should
   * be considered valid.  If a record has been in the cache for less than this
   * period fo time, then the cached record will be used instead of making a
   * name service call.  If a record has been in the cache for longer than this
   * period of time, then the cached record will only be used if it is not
   * possible to get an updated version of the record from the name service.
   *
   * @return  The length of time, in milliseconds, that cache records should be
   *          considered valid.
   */
  public int getTimeoutMillis()
  {
    return (int) timeoutMillis;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InetAddress getByName(@Nullable final String host)
         throws UnknownHostException, SecurityException
  {
    // Use the getAllByNameInternal method to get all addresses associated with
    // the provided name.  If there's only one name associated with the address,
    // then return that name.  If there are multiple names, then return one at
    // random.
    final InetAddress[] addresses = getAllByNameInternal(host);
    if (addresses.length == 1)
    {
      return addresses[0];
    }

    return addresses[ThreadLocalRandom.get().nextInt(addresses.length)];
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InetAddress[] getAllByName(@Nullable final String host)
         throws UnknownHostException, SecurityException
  {
    // Create a defensive copy of the address array so that the caller cannot
    // alter the original.
    final InetAddress[] addresses = getAllByNameInternal(host);
    return Arrays.copyOf(addresses, addresses.length);
  }



  /**
   * Retrieves an array of {@code InetAddress} objects that encapsulate all
   * known IP addresses associated with the provided host name.
   *
   * @param  host  The host name for which to retrieve the corresponding
   *               {@code InetAddress} objects.  It can be a resolvable name or
   *               a textual representation of an IP address.  If the provided
   *               name is the textual representation of an IPv6 address, then
   *               it can use either the form described in RFC 2373 or RFC 2732,
   *               or it can be an IPv6 scoped address.  If it is {@code null},
   *               then the returned address should represent an address of the
   *               loopback interface.
   *
   * @return  An array of {@code InetAddress} objects that encapsulate all known
   *          IP addresses associated with the provided host name.
   *
   * @throws  UnknownHostException  If the provided name cannot be resolved to
   *                                its corresponding IP addresses.
   *
   * @throws  SecurityException  If a security manager prevents the name
   *                             resolution attempt.
   */
  @NotNull()
  public InetAddress[] getAllByNameInternal(@Nullable final String host)
         throws UnknownHostException, SecurityException
  {
    // Get an all-lowercase representation of the provided host name.  Note that
    // the provided host name can be null, so we need to handle that possibility
    // as well.
    final String lowerHost;
    if (host == null)
    {
      lowerHost = "";
    }
    else
    {
      lowerHost = StaticUtils.toLowerCase(host);
    }


    // Get the appropriate record from the cache.  If there isn't a cached
    // then do perform a name service lookup and cache the result before
    // returning it.
    final ObjectPair<Long,InetAddress[]> cachedRecord =
         nameToAddressMap.get(lowerHost);
    if (cachedRecord == null)
    {
      return lookUpAndCache(host, lowerHost);
    }


    // If the cached record is not expired, then return its set of addresses.
    if (System.currentTimeMillis() <= cachedRecord.getFirst())
    {
      return cachedRecord.getSecond();
    }


    // The cached record is expired.  Try to get a new record from the name
    // service, and if that attempt succeeds, then cache the result before
    // returning it.  If the name service lookup fails, then fall back to using
    // the cached addresses even though they're expired.
    try
    {
      return lookUpAndCache(host, lowerHost);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return cachedRecord.getSecond();
    }
  }



  /**
   * Performs a name service lookup to retrieve all addresses for the provided
   * name.  If the lookup succeeds, then cache the result before returning it.
   *
   * @param  host       The host name for which to retrieve the corresponding
   *                    {@code InetAddress} objects.  It can be a resolvable
   *                    name or a textual representation of an IP address.  If
   *                    the provided name is the textual representation of an
   *                    IPv6 address, then it can use either the form described
   *                    in RFC 2373 or RFC 2732, or it can be an IPv6 scoped
   *                    address.  If it is {@code null}, then the returned
   *                    address should represent an address of the loopback
   *                    interface.
   * @param  lowerHost  An all-lowercase representation of the provided host
   *                    name, or an empty string if the provided host name is
   *                    {@code null}.  This will be the key under which the
   *                    record will be stored in the cache.
   *
   * @return  An array of {@code InetAddress} objects that represent all
   *          addresses for the provided name.
   *
   * @throws  UnknownHostException  If the provided name cannot be resolved to
   *                                its corresponding IP addresses.
   *
   * @throws  SecurityException  If a security manager prevents the name
   *                             resolution attempt.
   */
  @NotNull()
  private InetAddress[] lookUpAndCache(@Nullable final String host,
                                       @NotNull final String lowerHost)
         throws UnknownHostException, SecurityException
  {
    final InetAddress[] addresses = InetAddress.getAllByName(host);
    final long cacheRecordExpirationTime =
         System.currentTimeMillis() + timeoutMillis;
    final ObjectPair<Long,InetAddress[]> cacheRecord =
         new ObjectPair<>(cacheRecordExpirationTime, addresses);
    nameToAddressMap.put(lowerHost, cacheRecord);
    return addresses;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getHostName(@NotNull final InetAddress inetAddress)
  {
    // The default InetAddress.getHostName() method has the potential to perform
    // a name service lookup, which we want to avoid if at all possible.
    // However, if the provided inet address has a name associated with it, then
    // we'll want to use it.  Fortunately, we can tell if the provided address
    // has a name associated with it by looking at the toString method, which is
    // defined in the specification to be "hostName/ipAddress" if there is a
    // host name, or just "/ipAddress" if there is no associated host name and a
    // name service lookup would be required.  So look at the string
    // representation to extract the host name if it's available, but then fall
    // back to using the canonical name otherwise.
    final String stringRepresentation = String.valueOf(inetAddress);
    final int lastSlashPos = stringRepresentation.lastIndexOf('/');
    if (lastSlashPos > 0)
    {
      return stringRepresentation.substring(0, lastSlashPos);
    }

    return getCanonicalHostName(inetAddress);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getCanonicalHostName(@NotNull final InetAddress inetAddress)
  {
    // Get the appropriate record from the cache.  If there isn't a cached
    // then do perform a name service lookup and cache the result before
    // returning it.
    final ObjectPair<Long,String> cachedRecord =
         addressToNameMap.get(inetAddress);
    if (cachedRecord == null)
    {
      return lookUpAndCache(inetAddress, null);
    }


    // If the cached record is not expired, then return its canonical host name.
    if (System.currentTimeMillis() <= cachedRecord.getFirst())
    {
      return cachedRecord.getSecond();
    }


    // The cached record is expired.  Try to get a new record from the name
    // service, and if that attempt succeeds, then cache the result before
    // returning it.  If the name service lookup fails, then fall back to using
    // the cached canonical host name even though it's expired.
    return lookUpAndCache(inetAddress, cachedRecord.getSecond());
  }



  /**
   * Performs a name service lookup to retrieve the canonical host name for the
   * provided {@code InetAddress} object.  If the lookup succeeds, then cache
   * the result before returning it.  If the lookup fails (which will be
   * indicated by the returned name matching the textual representation of the
   * IP address for the provided {@code InetAddress} object) and the provided
   * cached result is not {@code null}, then the cached name will be returned,
   * but the cache will not be updated.
   *
   * @param  inetAddress  The address to use when performing the name service
   *                      lookup to retrieve the canonical name.  It must not be
   *                      {@code null}.
   * @param  cachedName   The cached name to be returned if the name service
   *                      lookup fails.  It may be {@code null} if there is no
   *                      cached name for the provided address.
   *
   * @return  The canonical host name resulting from the name service lookup,
   *          the cached name if the lookup failed and the cached name was
   *          non-{@code null}, or a textual representation of the IP address as
   *          a last resort.
   */
  @NotNull()
  private String lookUpAndCache(@NotNull final InetAddress inetAddress,
                                @Nullable final String cachedName)
  {
    final String canonicalHostName = inetAddress.getCanonicalHostName();
    if (canonicalHostName.equals(inetAddress.getHostAddress()))
    {
      // The name that we got back is a textual representation of the IP
      // address.  This suggests that either the canonical lookup failed because
      // of a problem while communicating with the name service, or that the
      // IP address is not mapped to a name.  If a cached name was provided,
      // then we'll return that.  Otherwise, we'll fall back to returning the
      // textual address.  In either case, we won't alter the cache.
      if (cachedName == null)
      {
        return canonicalHostName;
      }
      else
      {
        return cachedName;
      }
    }
    else
    {
      // The name service lookup succeeded, so cache the result before returning
      // it.
      final long cacheRecordExpirationTime =
           System.currentTimeMillis() + timeoutMillis;
      final ObjectPair<Long,String> cacheRecord =
           new ObjectPair<>(cacheRecordExpirationTime, canonicalHostName);
      addressToNameMap.put(inetAddress, cacheRecord);
      return canonicalHostName;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InetAddress getLocalHost()
         throws UnknownHostException, SecurityException
  {
    // If we don't have a cached version of the local host address, then
    // make a name service call to resolve it and store it in the cache before
    // returning it.
    final ObjectPair<Long,InetAddress> cachedAddress = localHostAddress.get();
    if (cachedAddress == null)
    {
      final InetAddress localHost = InetAddress.getLocalHost();
      final long expirationTime =
           System.currentTimeMillis() + timeoutMillis;
      localHostAddress.set(new ObjectPair<Long,InetAddress>(expirationTime,
           localHost));
      return localHost;
    }


    // If the cached address has not yet expired, then use the cached address.
    final long cachedRecordExpirationTime = cachedAddress.getFirst();
    if (System.currentTimeMillis() <= cachedRecordExpirationTime)
    {
      return cachedAddress.getSecond();
    }


    // The cached address is expired.  Make a name service call to get it again
    // and cache that result if we can.  If the name service lookup fails, then
    // return the cached version even though it's expired.
    try
    {
      final InetAddress localHost = InetAddress.getLocalHost();
      final long expirationTime =
           System.currentTimeMillis() + timeoutMillis;
      localHostAddress.set(new ObjectPair<Long,InetAddress>(expirationTime,
           localHost));
      return localHost;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return cachedAddress.getSecond();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InetAddress getLoopbackAddress()
  {
    // If we don't have a cached version of the loopback address, then make a
    // name service call to resolve it and store it in the cache before
    // returning it.
    final ObjectPair<Long,InetAddress> cachedAddress = loopbackAddress.get();
    if (cachedAddress == null)
    {
      final InetAddress address = InetAddress.getLoopbackAddress();
      final long expirationTime =
           System.currentTimeMillis() + timeoutMillis;
      loopbackAddress.set(new ObjectPair<Long,InetAddress>(expirationTime,
           address));
      return address;
    }


    // If the cached address has not yet expired, then use the cached address.
    final long cachedRecordExpirationTime = cachedAddress.getFirst();
    if (System.currentTimeMillis() <= cachedRecordExpirationTime)
    {
      return cachedAddress.getSecond();
    }


    // The cached address is expired.  Make a name service call to get it again
    // and cache that result if we can.  If the name service lookup fails, then
    // return the cached version even though it's expired.
    try
    {
      final InetAddress address = InetAddress.getLoopbackAddress();
      final long expirationTime =
           System.currentTimeMillis() + timeoutMillis;
      loopbackAddress.set(new ObjectPair<Long,InetAddress>(expirationTime,
           address));
      return address;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return cachedAddress.getSecond();
    }
  }



  /**
   * Clears all information from the name resolver cache.
   */
  public void clearCache()
  {
    localHostAddress.set(null);
    loopbackAddress.set(null);
    addressToNameMap.clear();
    nameToAddressMap.clear();
  }



  /**
   * Retrieves a handle to the map used to cache address-to-name lookups.  This
   * method should only be used for unit testing.
   *
   * @return  A handle to the address-to-name map.
   */
  @NotNull()
  Map<InetAddress,ObjectPair<Long,String>> getAddressToNameMap()
  {
    return addressToNameMap;
  }



  /**
   * Retrieves a handle to the map used to cache name-to-address lookups.  This
   * method should only be used for unit testing.
   *
   * @return  A handle to the name-to-address map.
   */
  @NotNull()
  Map<String,ObjectPair<Long,InetAddress[]>> getNameToAddressMap()
  {
    return nameToAddressMap;
  }



  /**
   * Retrieves a handle to the {@code AtomicReference} used to cache the local
   * host address.  This should only be used for testing.
   *
   * @return  A handle to the {@code AtomicReference} used to cache the local
   *          host address.
   */
  @NotNull()
  AtomicReference<ObjectPair<Long,InetAddress>> getLocalHostAddressReference()
  {
    return localHostAddress;
  }



  /**
   * Retrieves a handle to the {@code AtomicReference} used to cache the
   * loopback address.  This should only be used for testing.
   *
   * @return  A handle to the {@code AtomicReference} used to cache the
   *          loopback address.
   */
  @NotNull()
  AtomicReference<ObjectPair<Long,InetAddress>> getLoopbackAddressReference()
  {
    return loopbackAddress;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CachingNameResolver(timeoutMillis=");
    buffer.append(timeoutMillis);
    buffer.append(')');
  }
}
