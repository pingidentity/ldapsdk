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

import org.testng.annotations.Test;



/**
 * This class provides unit test coverage for the default name resolver.
 */
public final class DefaultNameResolverTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getByName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetByName()
         throws Exception
  {
    final InetAddress address =
         DefaultNameResolver.getInstance().getByName("www.pingidentity.com");
    assertNotNull(address);
  }



  /**
   * Tests the {@code getAllByName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAllByName()
         throws Exception
  {
    final InetAddress[] addresses = DefaultNameResolver.getInstance().
         getAllByName("www.pingidentity.com");
    assertNotNull(addresses);
    assertFalse(addresses.length == 0);
  }



  /**
   * Tests the {@code getHostName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetHostName()
         throws Exception
  {
    final InetAddress address =
         DefaultNameResolver.getInstance().getByName("www.pingidentity.com");
    assertNotNull(address);

    final String name = DefaultNameResolver.getInstance().getHostName(address);
    assertNotNull(name);
  }



  /**
   * Tests the {@code getCanonicalHostName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetCanonicalHostName()
         throws Exception
  {
    final InetAddress address =
         DefaultNameResolver.getInstance().getByName("www.pingidentity.com");
    assertNotNull(address);

    final String name =
         DefaultNameResolver.getInstance().getCanonicalHostName(address);
    assertNotNull(name);
  }



  /**
   * Tests the {@code getLocalHost} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLocalHost()
         throws Exception
  {
    final InetAddress localHostAddress =
         DefaultNameResolver.getInstance().getLocalHost();
    assertNotNull(localHostAddress);
  }



  /**
   * Tests the {@code getLoopbackAddress} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLoopbackAddress()
         throws Exception
  {
    final InetAddress loopbackAddress =
         DefaultNameResolver.getInstance().getLoopbackAddress();
    assertNotNull(loopbackAddress);

    final InetAddress ipv4Loopback = InetAddress.getByName("127.0.0.1");
    final InetAddress ipv6Loopback = InetAddress.getByName("::1");
    assertTrue(loopbackAddress.equals(ipv4Loopback) ||
         loopbackAddress.equals(ipv6Loopback));
  }



  /**
   * Tests the {@code setJVMSuccessfulLookupCacheTTLSeconds} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetJVMSuccessfulLookupCacheTTLSeconds()
         throws Exception
  {
    final String defaultTTL = System.getProperty("networkaddress.cache.ttl");

    NameResolver.setJVMSuccessfulLookupCacheTTLSeconds(1234);
    assertEquals(System.getProperty("networkaddress.cache.ttl"), "1234");

    NameResolver.setJVMSuccessfulLookupCacheTTLSeconds(5678);
    assertEquals(System.getProperty("networkaddress.cache.ttl"), "5678");

    NameResolver.setJVMSuccessfulLookupCacheTTLSeconds(-1);
    assertEquals(System.getProperty("networkaddress.cache.ttl"), "-1");

    NameResolver.setJVMSuccessfulLookupCacheTTLSeconds(0);
    assertEquals(System.getProperty("networkaddress.cache.ttl"), "0");

    NameResolver.setJVMSuccessfulLookupCacheTTLSeconds(-1234);
    assertEquals(System.getProperty("networkaddress.cache.ttl"), "-1");

    if (defaultTTL == null)
    {
      System.clearProperty("networkaddress.cache.ttl");
    }
    else
    {
      System.setProperty("networkaddress.cache.ttl", defaultTTL);
    }
  }



  /**
   * Tests the {@code setJVMUnsuccessfulLookupCacheTTLSeconds} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetJVMUnsuccessfulLookupCacheTTLSeconds()
         throws Exception
  {
    final String defaultTTL =
         System.getProperty("networkaddress.cache.negative.ttl");

    NameResolver.setJVMUnsuccessfulLookupCacheTTLSeconds(1234);
    assertEquals(System.getProperty("networkaddress.cache.negative.ttl"),
         "1234");

    NameResolver.setJVMUnsuccessfulLookupCacheTTLSeconds(5678);
    assertEquals(System.getProperty("networkaddress.cache.negative.ttl"),
         "5678");

    NameResolver.setJVMUnsuccessfulLookupCacheTTLSeconds(-1);
    assertEquals(System.getProperty("networkaddress.cache.negative.ttl"),
         "-1");

    NameResolver.setJVMUnsuccessfulLookupCacheTTLSeconds(0);
    assertEquals(System.getProperty("networkaddress.cache.negative.ttl"), "0");

    NameResolver.setJVMUnsuccessfulLookupCacheTTLSeconds(-1234);
    assertEquals(System.getProperty("networkaddress.cache.negative.ttl"), "-1");

    if (defaultTTL == null)
    {
      System.clearProperty("networkaddress.cache.negative.ttl");
    }
    else
    {
      System.setProperty("networkaddress.cache.negative.ttl", defaultTTL);
    }
  }



  /**
   * Tests the {@code toString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToString()
         throws Exception
  {
    assertNotNull(DefaultNameResolver.getInstance().toString());
  }
}
