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



import java.io.PrintStream;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import javax.naming.Context;

import org.testng.annotations.Test;

import com.unboundid.util.Debug;
import com.unboundid.util.NullOutputStream;



/**
 * This class provides a set of test cases for the SRVRecordSet class.
 */
public final class SRVRecordSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests general behavior for SRV record sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperation()
         throws Exception
  {
    final long expirationTime = System.currentTimeMillis() + 60000L;

    final SRVRecordSet s = new SRVRecordSet(expirationTime, Arrays.asList(
         new SRVRecord("1 1 389 ds1.east.example.com"),
         new SRVRecord("1 1 389 ds2.east.example.com"),
         new SRVRecord("2 1 389 ds1.central.example.com"),
         new SRVRecord("2 1 389 ds2.central.example.com"),
         new SRVRecord("3 1 389 ds1.west.example.com"),
         new SRVRecord("3 1 389 ds2.west.example.com")));

    assertNotNull(s);

    assertEquals(s.getExpirationTime(), expirationTime);
    assertFalse(s.isExpired());

    final List<SRVRecord> orderedRecords = s.getOrderedRecords();
    assertNotNull(orderedRecords);
    assertFalse(orderedRecords.isEmpty());
    assertEquals(orderedRecords.size(), 6);

    final Iterator<SRVRecord> recordIterator = orderedRecords.iterator();

    final SRVRecord r1 = recordIterator.next();
    assertEquals(r1.getPriority(), 1);
    assertTrue(r1.getAddress().endsWith(".east.example.com"));

    final SRVRecord r2 = recordIterator.next();
    assertEquals(r2.getPriority(), 1);
    assertTrue(r2.getAddress().endsWith(".east.example.com"));
    assertFalse(r1.getAddress().equals(r2.getAddress()));

    final SRVRecord r3 = recordIterator.next();
    assertEquals(r3.getPriority(), 2);
    assertTrue(r3.getAddress().endsWith(".central.example.com"));

    final SRVRecord r4 = recordIterator.next();
    assertEquals(r4.getPriority(), 2);
    assertTrue(r4.getAddress().endsWith(".central.example.com"));
    assertFalse(r3.getAddress().equals(r4.getAddress()));

    final SRVRecord r5 = recordIterator.next();
    assertEquals(r5.getPriority(), 3);
    assertTrue(r5.getAddress().endsWith(".west.example.com"));

    final SRVRecord r6 = recordIterator.next();
    assertEquals(r6.getPriority(), 3);
    assertTrue(r6.getAddress().endsWith(".west.example.com"));
    assertFalse(r5.getAddress().equals(r6.getAddress()));

    assertNotNull(s.toString());
  }



  /**
   * Tests expiration time behavior.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExpiration()
         throws Exception
  {
    final long futureExpirationTime = System.currentTimeMillis() + 60000L;
    final long pastExpirationTime = System.currentTimeMillis() - 60000L;

    final SRVRecordSet futureSet = new SRVRecordSet(futureExpirationTime,
         Arrays.asList(new SRVRecord("1 1 389 ldap.example.com")));
    assertEquals(futureSet.getExpirationTime(), futureExpirationTime);
    assertFalse(futureSet.isExpired());

    final SRVRecordSet pastSet = new SRVRecordSet(pastExpirationTime,
         Arrays.asList(new SRVRecord("1 1 389 ldap.example.com")));
    assertEquals(pastSet.getExpirationTime(), pastExpirationTime);
    assertTrue(pastSet.isExpired());
  }



  /**
   * Tests to ensure that weight is properly used when ordering records.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWeightOrdering()
         throws Exception
  {
    final long expirationTime = System.currentTimeMillis() + 60000L;

    final SRVRecordSet s = new SRVRecordSet(expirationTime, Arrays.asList(
         new SRVRecord("1 1 389 ds1.east.example.com"),
         new SRVRecord("1 10 389 ds2.east.example.com"),
         new SRVRecord("1 0 389 ds3.east.example.com"),
         new SRVRecord("2 20 389 ds1.central.example.com"),
         new SRVRecord("2 1 389 ds2.central.example.com"),
         new SRVRecord("2 0 389 ds3.central.example.com"),
         new SRVRecord("3 1 389 ds1.west.example.com"),
         new SRVRecord("3 1 389 ds2.west.example.com"),
         new SRVRecord("3 0 389 ds3.west.example.com")));

    int east1Count    = 0;
    int east2Count    = 0;
    int central1Count = 0;
    int central2Count = 0;
    int west1Count    = 0;
    int west2Count    = 0;

    // Get 10,000 ordered sets to have big enough sample size to create a good
    // degree of confidence.
    for (int i=0; i < 10000; i++)
    {
      final List<SRVRecord> orderedRecords = s.getOrderedRecords();

      assertNotNull(orderedRecords);
      assertEquals(orderedRecords.size(), 9);

      final Iterator<SRVRecord> iterator = orderedRecords.iterator();

      final SRVRecord r1 = iterator.next();
      final SRVRecord r2 = iterator.next();
      final SRVRecord r3 = iterator.next();
      final SRVRecord r4 = iterator.next();
      final SRVRecord r5 = iterator.next();
      final SRVRecord r6 = iterator.next();
      final SRVRecord r7 = iterator.next();
      final SRVRecord r8 = iterator.next();
      final SRVRecord r9 = iterator.next();

      if (r1.getAddress().equals("ds1.east.example.com"))
      {
        east1Count++;
        assertEquals(r2.getAddress(), "ds2.east.example.com");
      }
      else
      {
        east2Count++;
        assertEquals(r1.getAddress(), "ds2.east.example.com");
        assertEquals(r2.getAddress(), "ds1.east.example.com");
      }

      assertEquals(r3.getAddress(), "ds3.east.example.com");

      if (r4.getAddress().equals("ds1.central.example.com"))
      {
        central1Count++;
        assertEquals(r5.getAddress(), "ds2.central.example.com");
      }
      else
      {
        central2Count++;
        assertEquals(r4.getAddress(), "ds2.central.example.com");
        assertEquals(r5.getAddress(), "ds1.central.example.com");
      }

      assertEquals(r6.getAddress(), "ds3.central.example.com");

      if (r7.getAddress().equals("ds1.west.example.com"))
      {
        west1Count++;
        assertEquals(r8.getAddress(), "ds2.west.example.com");
      }
      else
      {
        west2Count++;
        assertEquals(r7.getAddress(), "ds2.west.example.com");
        assertEquals(r8.getAddress(), "ds1.west.example.com");
      }

      assertEquals(r9.getAddress(), "ds3.west.example.com");
    }

    // The east 2 server should have been first about 10 times as often as the
    // east 1 server.  We'll allow anywhere between 7.5 and 12.5.
    final double ratioEast = 1.0d * east2Count / east1Count;
    assertTrue(((ratioEast >= 7.5d) && (ratioEast <= 12.5d)),
         "east 1 first " + east1Count + "; east 2 first " + east2Count);

    // The central 1 server should have been first about 20 times as often as
    // the central 2 server.  We'll allow anywhere between 15 and 25.
    final double ratioCentral = 1.0d * central1Count / central2Count;
    assertTrue(((ratioCentral >= 15.0d) && (ratioCentral <= 25.0d)),
         "central 1 first " + central1Count + "; central 2 first " +
              central2Count);

    // Both the west 1 and west 2 servers should have been first about an equal
    // number of times.  We'll allow a ratio of anywhere between 0.75 and 1.25.
    final double ratioWest = 1.0d * west1Count / west2Count;
    assertTrue(((ratioWest >= 0.75d) && (ratioWest <= 1.25d)),
         "west 1 first " + west1Count + "; west 2 first " + west2Count);
  }



  /**
   * Tests the ability to retrieve and decode SRV record information from DNS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRetrieveFromDNS()
         throws Exception
  {
    // Create a simple test DNS server to use to process the request.
    final TestDNSSRVRecordServer
         dnsServer = new TestDNSSRVRecordServer(1389, 2389);
    dnsServer.start();

    final int dnsServerPort = dnsServer.getListenPort();
    assertTrue(dnsServerPort > 0);

    final boolean debugEnabled = Debug.debugEnabled();
    final PrintStream originalOut = System.out;
    final PrintStream originalErr = System.err;
    if (! debugEnabled)
    {
      Debug.setEnabled(true);
      System.setOut(NullOutputStream.getPrintStream());
      System.setErr(NullOutputStream.getPrintStream());
    }
    try
    {
      final String recordName = "_ldap._tcp.example.com";
      final String providerURL = "dns://localhost:" + dnsServerPort;
      final long ttlMillis = 60L * 60L * 1000L;

      final Hashtable<String,String> jndiProperties =
           new Hashtable<String,String>(2);
      jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY,
           "com.sun.jndi.dns.DnsContextFactory");
      jndiProperties.put(Context.PROVIDER_URL, providerURL);

      final SRVRecordSet recordSet = SRVRecordSet.getRecordSet(recordName,
           jndiProperties, ttlMillis);

      assertNotNull(recordSet);

      final List<SRVRecord> records = recordSet.getOrderedRecords();
      assertNotNull(records);
      assertEquals(records.size(), 2);

      final SRVRecord r1 = records.get(0);
      final SRVRecord r2 = records.get(1);

      assertEquals(r1.getAddress(), "localhost");
      assertEquals(r1.getPort(), 1389);
      assertEquals(r1.getPriority(), 1L);
      assertEquals(r1.getWeight(), 1L);

      assertEquals(r2.getAddress(), "localhost");
      assertEquals(r2.getPort(), 2389);
      assertEquals(r2.getPriority(), 2L);
      assertEquals(r2.getWeight(), 1L);
    }
    finally
    {
      if (! debugEnabled)
      {
        Debug.setEnabled(false);
        System.setOut(originalOut);
        System.setErr(originalErr);
      }
    }
  }
}
