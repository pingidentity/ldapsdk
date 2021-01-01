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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.naming.Context;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.RoundRobinDNSServerSet.AddressSelectionMode;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the round-robin DNS server set.
 */
public final class RoundRobinDNSServerSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests basic functionality for the server set without SSL.
   *
   * @param  mode  The address selection mode to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="selectionModes")
  public void testWithoutSSL(final AddressSelectionMode mode)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
         "localhost", ds.getListenPort(), mode, 30000L, null, null, null);

    assertNotNull(serverSet.getHostname());
    assertEquals(serverSet.getHostname(), "localhost");

    assertEquals(serverSet.getPort(), ds.getListenPort());

    assertNotNull(serverSet.getAddressSelectionMode());
    assertEquals(serverSet.getAddressSelectionMode(), mode);

    assertEquals(serverSet.getCacheTimeoutMillis(), 30000L);

    assertNull(serverSet.getProviderURL());

    assertNull(serverSet.getJNDIProperties());

    assertNotNull(serverSet.getDNSRecordTypes());
    assertEquals(serverSet.getDNSRecordTypes(), new String[] { "A" });

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());


    final GetEntryLDAPConnectionPoolHealthCheck successHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 10000L, true, false,
              false, true, true);
    final GetEntryLDAPConnectionPoolHealthCheck failureHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(
              "ou=missing,dc=example,dc=com", 10000L, true, false, false, true,
              true);

    for (int i=0; i < 5; i++)
    {
      LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn.getRootDSE());
      conn.close();

      conn = serverSet.getConnection(successHealthCheck);
      assertNotNull(conn.getRootDSE());
      conn.close();

      try
      {
        conn = serverSet.getConnection(failureHealthCheck);
        conn.close();
        fail("Expected an exception when trying to get a connection with a " +
             "health check failure.");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests basic functionality for the server set with SSL.
   *
   * @param  mode  The address selection mode to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="selectionModes")
  public void testWithSSL(final AddressSelectionMode mode)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
         "localhost", ds.getListenPort("LDAPS"), mode, -1L, null,
         sslUtil.createSSLSocketFactory(), opts);

    assertNotNull(serverSet.getHostname());
    assertEquals(serverSet.getHostname(), "localhost");

    assertEquals(serverSet.getPort(), ds.getListenPort("LDAPS"));

    assertNotNull(serverSet.getAddressSelectionMode());
    assertEquals(serverSet.getAddressSelectionMode(), mode);

    assertEquals(serverSet.getCacheTimeoutMillis(), 0L);

    assertNull(serverSet.getProviderURL());

    assertNull(serverSet.getJNDIProperties());

    assertNotNull(serverSet.getDNSRecordTypes());
    assertEquals(serverSet.getDNSRecordTypes(), new String[] { "A" });

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());


    final GetEntryLDAPConnectionPoolHealthCheck successHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 10000L, true, false,
              false, true, true);
    final GetEntryLDAPConnectionPoolHealthCheck failureHealthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck(
              "ou=missing,dc=example,dc=com", 10000L, true, false, false, true,
              true);

    for (int i=0; i < 5; i++)
    {
      LDAPConnection conn = serverSet.getConnection();
      assertNotNull(conn.getRootDSE());
      conn.close();

      conn = serverSet.getConnection(successHealthCheck);
      assertNotNull(conn.getRootDSE());
      conn.close();

      try
      {
        conn = serverSet.getConnection(failureHealthCheck);
        conn.close();
        fail("Expected an exception when trying to get a connection with a " +
             "health check failure.");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }
  }



  /**
   * Tests the ability to retrieve addresses from DNS.  This method requires
   * Internet access and a valid DNS setup for complete processing.  Note that
   * this method won't actually attempt to establish any LDAP connections, but
   * it can at least be used to test the DNS-related code in the server set.
   *
   * @param  mode  The address selection mode to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="selectionModes")
  public void testDNSProvider(final AddressSelectionMode mode)
         throws Exception
  {
    // NOTE:  At the present time, www.google.com is known to use a round-robin
    // DNS configuration.
    final Properties jndiProperties = new Properties();
    jndiProperties.setProperty("com.example.jndi.dns.recursion", "true");
    jndiProperties.setProperty("com.example.jndi.dns.timeout.initial", "30000");
    jndiProperties.setProperty("com.example.jndi.dns.timeout.retries", "3");

    final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
         "www.google.com", 80, mode, 60000L, "dns:", jndiProperties,
         new String[] { "A" }, null, null);

    assertNotNull(serverSet.getHostname());
    assertEquals(serverSet.getHostname(), "www.google.com");

    assertEquals(serverSet.getPort(), 80);

    assertNotNull(serverSet.getAddressSelectionMode());
    assertEquals(serverSet.getAddressSelectionMode(), mode);

    assertEquals(serverSet.getCacheTimeoutMillis(), 60000L);

    assertNotNull(serverSet.getProviderURL());
    assertEquals(serverSet.getProviderURL(), "dns:");

    assertNotNull(serverSet.getJNDIProperties());
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.INITIAL_CONTEXT_FACTORY));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         Context.PROVIDER_URL));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.recursion"));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.timeout.initial"));
    assertTrue(serverSet.getJNDIProperties().containsKey(
         "com.example.jndi.dns.timeout.retries"));

    assertNotNull(serverSet.getDNSRecordTypes());
    assertEquals(serverSet.getDNSRecordTypes(), new String[] { "A" });

    assertNotNull(serverSet.getSocketFactory());

    assertNotNull(serverSet.getConnectionOptions());

    assertNotNull(serverSet.toString());

    final InetAddress[] resolvedAddresses;
    try
    {
      resolvedAddresses = serverSet.resolveHostname();
    }
    catch (final Exception e)
    {
      // This isn't good, but we won't consider it a test failure since this
      // could indicate that there is no internet access available or no valid
      // DNS configuration.  We just won't run any further tests.
      return;
    }


    // Make sure that all the addresses have a hostname of "www.google.com" and
    // a non-null IP address.  Make sure that all of the IP addresses are
    // different.
    final LinkedHashSet<String> ipAddresses =
         new LinkedHashSet<String>(resolvedAddresses.length);
    for (final InetAddress a : resolvedAddresses)
    {
      assertEquals(a.getHostName(), "www.google.com");

      final String ipAddress = a.getHostAddress();
      assertNotNull(ipAddress);
      assertFalse(ipAddresses.contains(ipAddress));
      ipAddresses.add(ipAddress);
    }
  }



  /**
   * Tests failover ordering with a set of default addresses rather than relying
   * on a particular name service configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailoverOrdering()
         throws Exception
  {
    System.setProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES,
         "1.2.3.4,5.6.7.8,9.10.11.12,13.14.15.16,17.18.19.20");

    try
    {
      final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
           "directory.example.com", 389, AddressSelectionMode.FAILOVER,
           30000L, null, null, null);

      final InetAddress[] resolvedAddresses = serverSet.resolveHostname();
      assertNotNull(resolvedAddresses);
      assertEquals(resolvedAddresses.length, 5);

      final InetAddress[] reResolvedAddresses = serverSet.resolveHostname();
      assertNotNull(reResolvedAddresses);
      assertEquals(reResolvedAddresses, resolvedAddresses);

      final List<InetAddress> orderedAddresses =
           serverSet.orderAddresses(resolvedAddresses);
      for (int i=0; i < 100; i++)
      {
        assertEquals(serverSet.orderAddresses(resolvedAddresses),
             orderedAddresses);
      }
    }
    finally
    {
      System.clearProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES);
    }
  }



  /**
   * Tests round-robin ordering with a set of default addresses rather than
   * relying on a particular name service configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoundRobinOrdering()
         throws Exception
  {
    System.setProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES,
         "1.2.3.4,5.6.7.8,9.10.11.12,13.14.15.16,17.18.19.20");

    try
    {
      final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
           "directory.example.com", 389, AddressSelectionMode.ROUND_ROBIN,
           0L, null, null, null);

      final InetAddress[] resolvedAddresses = serverSet.resolveHostname();
      assertNotNull(resolvedAddresses);
      assertEquals(resolvedAddresses.length, 5);

      final List<InetAddress> l1 = serverSet.orderAddresses(resolvedAddresses);
      assertEquals(l1, Arrays.asList(resolvedAddresses));

      final List<InetAddress> l2 = serverSet.orderAddresses(resolvedAddresses);
      assertFalse(l2.equals(l1));
      assertEquals(l2, shiftLeft(l1));

      final List<InetAddress> l3 = serverSet.orderAddresses(resolvedAddresses);
      assertFalse(l3.equals(l2));
      assertEquals(l3, shiftLeft(l2));

      final List<InetAddress> l4 = serverSet.orderAddresses(resolvedAddresses);
      assertFalse(l4.equals(l3));
      assertEquals(l4, shiftLeft(l3));

      final List<InetAddress> l5 = serverSet.orderAddresses(resolvedAddresses);
      assertFalse(l5.equals(l4));
      assertEquals(l5, shiftLeft(l4));


      for (int i=0; i < 100; i++)
      {
        assertEquals(serverSet.orderAddresses(resolvedAddresses), l1);
        assertEquals(serverSet.orderAddresses(resolvedAddresses), l2);
        assertEquals(serverSet.orderAddresses(resolvedAddresses), l3);
        assertEquals(serverSet.orderAddresses(resolvedAddresses), l4);
        assertEquals(serverSet.orderAddresses(resolvedAddresses), l5);
      }
    }
    finally
    {
      System.clearProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES);
    }
  }



  /**
   * Creates a new list with the contents of the provided list shifted one to
   * the left so that the first element of the new list is the second element
   * of the original list, the second element of the new list is the third
   * element of the original list, etc., and the last element of the new list
   * is the first element of the original list.
   *
   * @param  addresses  The list of addresses to be shifted.
   *
   * @return  A list with the shifted addresses.
   */
  private static List<InetAddress> shiftLeft(final List<InetAddress> addresses)
  {
    final ArrayList<InetAddress> l = new ArrayList<InetAddress>(addresses);
    final InetAddress a = l.remove(0);
    l.add(a);
    return l;
  }



  /**
   * Tests round-robin ordering with a set of default addresses rather than
   * relying on a particular name service configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomOrdering()
         throws Exception
  {
    System.setProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES,
         "1.2.3.4,5.6.7.8,9.10.11.12,13.14.15.16,17.18.19.20");

    try
    {
      final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
           "directory.example.com", 389, AddressSelectionMode.RANDOM,
           0L, null, null, null);

      final InetAddress[] resolvedAddresses = serverSet.resolveHostname();
      assertNotNull(resolvedAddresses);
      assertEquals(resolvedAddresses.length, 5);

      final LinkedHashSet<String> addrStrings = new LinkedHashSet<String>(1000);
      for (int i=0; i < 1000; i++)
      {
        addrStrings.add(
             concatAddresses(serverSet.orderAddresses(resolvedAddresses)));
      }

      assertTrue(addrStrings.size() > 5);
    }
    finally
    {
      System.clearProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES);
    }
  }



  /**
   * Creates a string comprised of the concatenated IP addresses of the provided
   * Inet Address objects in the order they appear in the list.
   *
   * @param  addresses  The list of addresses to process.
   *
   * @return  The string containing the concatenated address list.
   */
  private static String concatAddresses(final List<InetAddress> addresses)
  {
    final StringBuilder buffer = new StringBuilder();

    final Iterator<InetAddress> iterator = addresses.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().getHostAddress());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    return buffer.toString();
  }



  /**
   * Tests the behavior when given a hostname that cannot be resolved when not
   * forced to use DNS to make the determination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testUnresolvableAddressNonForcedDNS()
         throws Exception
  {
    final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
         "does.not.resolve.example.com", 389, AddressSelectionMode.RANDOM,
         0L, null, null, null);
    serverSet.resolveHostname();
  }



  /**
   * Tests the behavior when given a hostname that cannot be resolved when
   * forced to use DNS to make the determination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testUnresolvableAddressForcedDNS()
         throws Exception
  {
    final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
         "does.not.resolve.example.com", 389, AddressSelectionMode.RANDOM,
         0L, "dns:", null, null);
    serverSet.resolveHostname();
  }



  /**
   * Tests the behavior of the getDefaultAddresses method when the address
   * property isn't valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDefaultAddressesInvalid()
         throws Exception
  {
    System.setProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES,
         "1234.5678.9101112.13141516");

    try
    {
      final RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(
           "directory.example.com", 389, AddressSelectionMode.RANDOM,
           0L, null, null, null);

      assertNull(serverSet.getDefaultAddresses());
    }
    finally
    {
      System.clearProperty(RoundRobinDNSServerSet.PROPERTY_DEFAULT_ADDRESSES);
    }
  }



  /**
   * Provides basic coverage for the selection modes enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelectionModes()
         throws Exception
  {
    assertNotNull(AddressSelectionMode.values());
    assertEquals(AddressSelectionMode.values().length, 3);

    for (final AddressSelectionMode m : AddressSelectionMode.values())
    {
      assertNotNull(AddressSelectionMode.valueOf(m.name()));
      assertEquals(AddressSelectionMode.valueOf(m.name()), m);

      assertNotNull(m.toString());

      m.ordinal();
      m.hashCode();
      assertTrue(m.equals(m));
    }

    try
    {
      AddressSelectionMode.valueOf("undefined");
      fail("Expected ane exception when trying to get an undefined mode");
    }
    catch (final Exception e)
    {
      // This was expected.
    }
  }



  /**
   * Retrieves the selection modes that may be used for testing.
   *
   * @return  The selection modes that may be used for testing.
   */
  @DataProvider(name="selectionModes")
  public Object[][] getSelectionModes()
  {
    return new Object[][]
    {
      new Object[]
      {
        AddressSelectionMode.FAILOVER,
      },

      new Object[]
      {
        AddressSelectionMode.RANDOM,
      },

      new Object[]
      {
        AddressSelectionMode.ROUND_ROBIN,
      }
    };
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final RoundRobinDNSServerSet.AddressSelectionMode value :
         RoundRobinDNSServerSet.AddressSelectionMode.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(
             RoundRobinDNSServerSet.AddressSelectionMode.forName(name));
        assertEquals(
             RoundRobinDNSServerSet.AddressSelectionMode.forName(name), value);
      }
    }

    assertNull(RoundRobinDNSServerSet.AddressSelectionMode.forName(
         "some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
