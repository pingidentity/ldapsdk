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

import org.testng.annotations.Test;

import com.unboundid.util.ObjectPair;
import com.unboundid.util.args.IPAddressArgumentValueValidator;



/**
 * This class provides a set of test cases for the caching name resolver.
 */
public final class CachingNameResolverTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the resolver with the default timeout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultTimeout()
         throws Exception
  {
    // Test the settings for an empty cache.
    final CachingNameResolver nameResolver = new CachingNameResolver();

    assertEquals(nameResolver.getTimeoutMillis(),
         1 * // 1 hour
         60 * // 60 minutes per hour
         60 * // 60 seconds per minute
         1000); // 1000 milliseconds per second


    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());

    assertNotNull(nameResolver.toString());


    // Test the getByName method.  This should require a name service lookup,
    // but make sure it gets stored in the cache.
    final InetAddress getByNameAddress1 =
         nameResolver.getByName("www.github.com");
    assertNotNull(getByNameAddress1);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Perform the same lookup again.  This time it should get the value from
    // the cache.  Note that when we use getByName for a name that resolves to
    // multiple addresses, the address that getByName returns is randomized, so
    // we can't guarantee that this result matches the one we got before.
    final InetAddress getByNameAddress2 =
         nameResolver.getByName("www.github.com");
    assertNotNull(getByNameAddress2);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Use the getAllByName method.  This should use the same cached
    // information as the previous lookups.
    final InetAddress[] getAllByNameAddresses =
         nameResolver.getAllByName("www.github.com");
    assertNotNull(getAllByNameAddresses);
    assertTrue(getAllByNameAddresses.length > 0);

    boolean foundGetByNameAddress1 = false;
    boolean foundGetByNameAddress2 = false;
    for (final InetAddress address : getAllByNameAddresses)
    {
      if (address.equals(getByNameAddress1))
      {
        foundGetByNameAddress1 = true;
      }
      if (address.equals(getByNameAddress2))
      {
        foundGetByNameAddress2 = true;
      }
    }
    assertTrue(foundGetByNameAddress1);
    assertTrue(foundGetByNameAddress2);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Look up the hostname for an InetAddress that we create from its IP
    // address.  This name should not be cached, so it will require a name
    // service lookup.
    final InetAddress addressForIP =
         InetAddress.getByName(getByNameAddress1.getHostAddress());
    final String hostName = nameResolver.getHostName(addressForIP);
    assertNotNull(hostName);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Look up the canonical hostname for the given address.  This should use
    // the cached lookup from the getHostName call.
    final String canonicalHostName =
         nameResolver.getCanonicalHostName(addressForIP);
    assertNotNull(canonicalHostName);
    assertEquals(canonicalHostName, hostName);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Get the local host address.  The first time should not be cached, so it
    // will require a name service lookup.
    final InetAddress localHost1 = nameResolver.getLocalHost();
    assertNotNull(localHost1);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNotNull(nameResolver.getLocalHostAddressReference().get());
    assertEquals(nameResolver.getLocalHostAddressReference().get().getSecond(),
         localHost1);

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Re-retrieve the local host address.  This time it should be cached.
    final InetAddress localHost2 = nameResolver.getLocalHost();
    assertNotNull(localHost2);
    assertEquals(localHost2, localHost1);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNotNull(nameResolver.getLocalHostAddressReference().get());
    assertEquals(nameResolver.getLocalHostAddressReference().get().getSecond(),
         localHost2);

    assertNull(nameResolver.getLoopbackAddressReference().get());


    // Get the loopback address.  This won't be cached, so it will require a
    // lookup.
    final InetAddress loopbackAddress1 = nameResolver.getLoopbackAddress();
    assertNotNull(loopbackAddress1);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNotNull(nameResolver.getLocalHostAddressReference().get());
    assertEquals(nameResolver.getLocalHostAddressReference().get().getSecond(),
         localHost1);

    assertNotNull(nameResolver.getLoopbackAddressReference().get());
    assertEquals(nameResolver.getLoopbackAddressReference().get().getSecond(),
         loopbackAddress1);


    // Re-get the loopback address.  This should be cached.
    final InetAddress loopbackAddress2 = nameResolver.getLoopbackAddress();
    assertNotNull(loopbackAddress2);
    assertEquals(loopbackAddress2, loopbackAddress1);

    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(
         getByNameAddress1));

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(
         "www.github.com"));

    assertNotNull(nameResolver.getLocalHostAddressReference().get());
    assertEquals(nameResolver.getLocalHostAddressReference().get().getSecond(),
         localHost1);

    assertNotNull(nameResolver.getLoopbackAddressReference().get());
    assertEquals(nameResolver.getLoopbackAddressReference().get().getSecond(),
         loopbackAddress1);


    // Clear the cache and make sure that everything really does get cleared.
    nameResolver.clearCache();

    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());
  }



  /**
   * Tests the behavior of the resolver with a non-default timeout.  It will be
   * a very short timeout, so we can make sure that cache expiration works.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultTimeout()
         throws Exception
  {
    // Test the settings for an empty cache.
    final CachingNameResolver nameResolver =
         new CachingNameResolver(1);

    assertEquals(nameResolver.getTimeoutMillis(), 1);


    assertNotNull(nameResolver.getAddressToNameMap());
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());

    assertNotNull(nameResolver.getNameToAddressMap());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());

    assertNull(nameResolver.getLocalHostAddressReference().get());

    assertNull(nameResolver.getLoopbackAddressReference().get());

    assertNotNull(nameResolver.toString());


    // Test the methods to get the various addresses when none of them should be
    // cached.
    final long earliestInitialExpirationTime = System.currentTimeMillis() + 1L;

    final InetAddress getByNameAddress =
         nameResolver.getByName("www.github.com");
    assertNotNull(getByNameAddress);

    assertNotNull(nameResolver.getAllByName("www.github.com"));

    final String hostName = nameResolver.getCanonicalHostName(getByNameAddress);
    assertNotNull(hostName);

    assertNotNull(nameResolver.getLocalHost());

    assertNotNull(nameResolver.getLoopbackAddress());

    final long latestInitialExpirationTime = System.currentTimeMillis() + 1L;


    // Make sure that the lookups are cached, and remember the timestamps for
    // the cached records.
    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size() ,1);

    final long initialCachedAddressExpirationTime =
         nameResolver.getAddressToNameMap().get(getByNameAddress).getFirst();
    assertTrue(initialCachedAddressExpirationTime >=
         earliestInitialExpirationTime);
    assertTrue(initialCachedAddressExpirationTime <=
         latestInitialExpirationTime);

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);

    final long initialCachedNameExpirationTime = nameResolver.
         getNameToAddressMap().get("www.github.com").getFirst();
    assertTrue(initialCachedNameExpirationTime >=
         earliestInitialExpirationTime);
    assertTrue(initialCachedNameExpirationTime <= latestInitialExpirationTime);

    assertNotNull(nameResolver.getLocalHostAddressReference().get());

    final long initialCachedLocalHostExpirationTime =
         nameResolver.getLocalHostAddressReference().get().getFirst();
    assertTrue(initialCachedLocalHostExpirationTime >=
         earliestInitialExpirationTime);
    assertTrue(initialCachedLocalHostExpirationTime <=
         latestInitialExpirationTime);

    assertNotNull(nameResolver.getLoopbackAddressReference().get());

    final long initialCachedLoopbackAddressExpirationTime =
         nameResolver.getLoopbackAddressReference().get().getFirst();
    assertTrue(initialCachedLoopbackAddressExpirationTime >=
         earliestInitialExpirationTime);
    assertTrue(initialCachedLoopbackAddressExpirationTime <=
         latestInitialExpirationTime);


    // Sleep for at least 10 milliseconds so that the cached information will be
    // expired.  Then re-get the same values.
    Thread.sleep(10L);

    final long earliestSecondExpirationTime = System.currentTimeMillis() + 1L;

    nameResolver.getByName("www.github.com");
    nameResolver.getCanonicalHostName(getByNameAddress);
    nameResolver.getLocalHost();
    nameResolver.getLoopbackAddress();

    final long latestSecondExpirationTime = System.currentTimeMillis() + 1L;


    // Re-examine the cache and make sure that all the expiration times are
    // different than they were before.
    assertNotNull(nameResolver.getAddressToNameMap());
    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size() ,1);

    final long secondCachedAddressExpirationTime =
         nameResolver.getAddressToNameMap().get(getByNameAddress).getFirst();
    assertFalse(secondCachedAddressExpirationTime ==
         initialCachedAddressExpirationTime);
    assertTrue(secondCachedAddressExpirationTime >=
         earliestSecondExpirationTime);
    assertTrue(secondCachedAddressExpirationTime <= latestSecondExpirationTime);

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);

    final long secondCachedNameExpirationTime = nameResolver.
         getNameToAddressMap().get("www.github.com").getFirst();
    assertFalse(secondCachedNameExpirationTime ==
         initialCachedNameExpirationTime);
    assertTrue(secondCachedNameExpirationTime >= earliestSecondExpirationTime);
    assertTrue(secondCachedNameExpirationTime <= latestSecondExpirationTime);

    assertNotNull(nameResolver.getLocalHostAddressReference().get());

    final long secondCachedLocalHostExpirationTime =
         nameResolver.getLocalHostAddressReference().get().getFirst();
    assertFalse(secondCachedLocalHostExpirationTime ==
         initialCachedLocalHostExpirationTime);
    assertTrue(secondCachedLocalHostExpirationTime >=
         earliestSecondExpirationTime);
    assertTrue(secondCachedLocalHostExpirationTime <=
         latestSecondExpirationTime);

    assertNotNull(nameResolver.getLoopbackAddressReference().get());

    final long secondCachedLoopbackAddressExpirationTime =
         nameResolver.getLoopbackAddressReference().get().getFirst();
    assertFalse(secondCachedLoopbackAddressExpirationTime ==
         initialCachedLoopbackAddressExpirationTime);
    assertTrue(secondCachedLoopbackAddressExpirationTime >=
         earliestSecondExpirationTime);
    assertTrue(secondCachedLoopbackAddressExpirationTime <=
         latestSecondExpirationTime);
  }



  /**
   * Tests the behavior of the {@code getByName} and {@code getAllByName}
   * methods with a cached name that resolves to a single address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetByNameWithSingleCachedAddress()
         throws Exception
  {
    final CachingNameResolver nameResolver = new CachingNameResolver();

    final InetAddress dummyAddress =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 });

    nameResolver.getNameToAddressMap().put("dummy.example.com",
         new ObjectPair<Long,InetAddress[]>(
              (System.currentTimeMillis() + 3_600_000L),
              new InetAddress[] { dummyAddress }));

    assertNotNull(nameResolver.getByName("dummy.example.com"));
    assertEquals(nameResolver.getByName("dummy.example.com"), dummyAddress);

    assertNotNull(nameResolver.getAllByName("dummy.example.com"));
    assertEquals(nameResolver.getAllByName("dummy.example.com").length, 1);
    assertEquals(nameResolver.getAllByName("dummy.example.com")[0],
         dummyAddress);
  }



  /**
   * Tests the behavior of the {@code getByName} and {@code getAllByName}
   * methods with a cached name that resolves to a single address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetByNameWithMultipleCachedAddresses()
         throws Exception
  {
    final CachingNameResolver nameResolver = new CachingNameResolver();

    final InetAddress dummyAddress1 =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 });
    final InetAddress dummyAddress2 =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 5 });
    final InetAddress dummyAddress3 =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 6 });

    nameResolver.getNameToAddressMap().put("dummy.example.com",
         new ObjectPair<Long,InetAddress[]>(
              (System.currentTimeMillis() + 3_600_000L),
              new InetAddress[]
              {
                dummyAddress1,
                dummyAddress2,
                dummyAddress3
              }));

    assertNotNull(nameResolver.getAllByName("dummy.example.com"));
    assertEquals(nameResolver.getAllByName("dummy.example.com").length, 3);
    assertEquals(nameResolver.getAllByName("dummy.example.com"),
         new InetAddress[] { dummyAddress1, dummyAddress2, dummyAddress3 });

    int dummyAddress1Count = 0;
    int dummyAddress2Count = 0;
    int dummyAddress3Count = 0;
    for (int i=0; i < 1000; i++)
    {
      final InetAddress address = nameResolver.getByName("dummy.example.com");
      if (address.equals(dummyAddress1))
      {
        dummyAddress1Count++;
      }
      else if (address.equals(dummyAddress2))
      {
        dummyAddress2Count++;
      }
      else if (address.equals(dummyAddress3))
      {
        dummyAddress3Count++;
      }
      else
      {
        fail("Found an unexpected address");
      }
    }

    assertTrue(dummyAddress1Count >= 100);
    assertTrue(dummyAddress2Count >= 100);
    assertTrue(dummyAddress3Count >= 100);
  }



  /**
   * Tests the {@code getByName} and {@code getAllByName} methods when provided
   * with a null argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetByNameNull()
         throws Exception
  {
    final CachingNameResolver nameResolver = new CachingNameResolver();

    final InetAddress address = nameResolver.getByName(null);
    assertNotNull(address);

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(""));

    nameResolver.clearCache();

    assertNotNull(nameResolver.getNameToAddressMap());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());


    final InetAddress[] addresses = nameResolver.getAllByName(null);
    assertNotNull(addresses);

    assertNotNull(nameResolver.getNameToAddressMap());
    assertFalse(nameResolver.getNameToAddressMap().isEmpty());
    assertEquals(nameResolver.getNameToAddressMap().size(), 1);
    assertTrue(nameResolver.getNameToAddressMap().containsKey(""));
  }



  /**
   * Tests the {@code getByName} and {@code getAllByName} methods with a name
   * that does not resolve to an IP address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void getGetByNameForUnresolvableName()
         throws Exception
  {
    final CachingNameResolver nameResolver = new CachingNameResolver();


    // First, try with an empty cache so that we'll have to do a name service
    // lookup.
    final String mixedCaseName = "ThisShouldNotResolve.example.com";
    final String lowerCaseName = mixedCaseName.toLowerCase();

    try
    {
      final InetAddress address = nameResolver.getByName(mixedCaseName);

      // If we got here, then it means that the name actually does resolve, and
      // it doesn't make sense to continue.  Just make sure that the resolved
      // address is non-null, since that method should never return null.
      assertNotNull(address);
      return;
    }
    catch (final UnknownHostException e)
    {
      // This was expected.  We can continue with the test.
    }


    // Make sure that we get a similar failure when using getAllByName.
    try
    {
      nameResolver.getByName(mixedCaseName);
      fail("Expected a failure for an unresolvable name");
    }
    catch (final UnknownHostException e)
    {
      // This was expected.  We can continue with the test.
    }


    // Next, put the address in the cache with a non-expired timestamp and make
    // sure that we can resolve it now.
    final InetAddress dummyAddress =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 });
    nameResolver.getNameToAddressMap().put(lowerCaseName,
         new ObjectPair<Long,InetAddress[]>(
              (System.currentTimeMillis() + 3_600_000L),
              new InetAddress[] { dummyAddress }));

    final InetAddress address = nameResolver.getByName(mixedCaseName);
    assertNotNull(address);
    assertEquals(address, dummyAddress);

    final InetAddress[] addresses = nameResolver.getAllByName(mixedCaseName);
    assertNotNull(addresses);
    assertEquals(addresses.length, 1);
    assertEquals(addresses[0], dummyAddress);


    // Put the address in the cache with an expired timestamp and make sure that
    // we still get the cached version because the lookup attempts fail.
    nameResolver.getNameToAddressMap().put(lowerCaseName,
         new ObjectPair<Long,InetAddress[]>(
              (System.currentTimeMillis() - 3_600_000L),
              new InetAddress[] { dummyAddress }));

    assertEquals(nameResolver.getByName(mixedCaseName), address);

    assertEquals(nameResolver.getAllByName(mixedCaseName),
         new InetAddress[] { dummyAddress });
  }



  /**
   * Tests the behavior for the {@code getHostName} method for an
   * {@code InetAddress} that does and does not have a host name associated with
   * it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetHostNameWithAssociatedName()
         throws Exception
  {
    // Perform a name service lookup to get the InetAddress for the
    final InetAddress wwwGitHubAddress =
         InetAddress.getByName("www.github.com");
    final InetAddress addressFromIP =
         InetAddress.getByName(wwwGitHubAddress.getHostAddress());
    final InetAddress wwwAddress =
         InetAddress.getByAddress("www", addressFromIP.getAddress());


    final CachingNameResolver nameResolver = new CachingNameResolver();


    // Get the host name for the InetAddress that we created with a name and IP
    // address.  Make sure that no name service lookup is performed.
    final String wwwHostName =
         nameResolver.getHostName(wwwAddress);
    assertNotNull(wwwHostName);
    assertEquals(wwwHostName, "www");

    assertTrue(nameResolver.getAddressToNameMap().isEmpty());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());


    // Get the host name for the InetAddress that we created from a lookup of
    // a name of "www.github.com".  It should have a host name equal to
    // the name we provided when looking it up.  Make sure that no name service
    // lookup is performed in this case, either.
    final String wwwGitHubHostName =
         nameResolver.getHostName(wwwGitHubAddress);
    assertNotNull(wwwGitHubHostName);
    assertEquals(wwwGitHubHostName, "www.github.com");

    assertTrue(nameResolver.getAddressToNameMap().isEmpty());
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());


    // Get the host name for the InetAddress that we created from an IP
    // address.  This won't have a host name associated with it, so it will
    // require a name service lookup.
    final String hostNameFromIP = nameResolver.getHostName(addressFromIP);
    assertNotNull(hostNameFromIP);
    assertFalse(hostNameFromIP.isEmpty());

    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(addressFromIP));
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());


    // Make sure that all three addresses resolve to the same canonical name.
    final String canonicalName1 =
         nameResolver.getCanonicalHostName(wwwAddress);
    assertNotNull(canonicalName1);

    final String canonicalName2 =
         nameResolver.getCanonicalHostName(wwwGitHubAddress);
    assertNotNull(canonicalName2);
    assertEquals(canonicalName2, canonicalName1);

    final String canonicalName3 =
         nameResolver.getCanonicalHostName(addressFromIP);
    assertNotNull(canonicalName3);
    assertEquals(canonicalName3, canonicalName1);

    assertFalse(nameResolver.getAddressToNameMap().isEmpty());
    assertEquals(nameResolver.getAddressToNameMap().size(), 1);
    assertTrue(nameResolver.getAddressToNameMap().containsKey(addressFromIP));
    assertTrue(nameResolver.getNameToAddressMap().isEmpty());
  }



  /**
   * Tests the {@code getHostName} and {@code getCanonicalHostName} methods
   * for an address that does not resolve to a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetHostNameForUnresolvableAddress()
         throws Exception
  {
    final CachingNameResolver nameResolver = new CachingNameResolver();

    final InetAddress address =
         InetAddress.getByAddress(new byte[] { 1, 2, 3, 4 });

    final String defaultName = nameResolver.getHostName(address);
    assertNotNull(defaultName);

    final String defaultCanonicalName =
         nameResolver.getCanonicalHostName(address);
    assertNotNull(defaultCanonicalName);
    assertEquals(defaultCanonicalName, defaultName);

    if (! IPAddressArgumentValueValidator.isValidNumericIPAddress(defaultName))
    {
      // It looks like the actually does resolve to a name.  This is unexpected,
      // but we can't really do any more testing in this method.
    }


    // Since the name didn't resolve, make sure it's not cached.
    assertTrue(nameResolver.getAddressToNameMap().isEmpty());


    // Put a non-expired mapping in the cache and make sure we get it back when
    // re-trying the lookups.
    nameResolver.getAddressToNameMap().put(address,
         new ObjectPair<Long,String>(
              (System.currentTimeMillis() + 3_600_000), "dummy.example.com"));

    assertEquals(nameResolver.getHostName(address), "dummy.example.com");

    assertEquals(nameResolver.getCanonicalHostName(address),
         "dummy.example.com");


    // Put an expired mapping in the cache and make sure that we still get it
    // back even though it's expired because the name can't be resolved.
    nameResolver.getAddressToNameMap().put(address,
         new ObjectPair<Long,String>(
              (System.currentTimeMillis() - 3_600_000), "dummy.example.com"));

    assertEquals(nameResolver.getHostName(address), "dummy.example.com");

    assertEquals(nameResolver.getCanonicalHostName(address),
         "dummy.example.com");
  }
}
