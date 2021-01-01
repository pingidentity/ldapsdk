/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the
 * {@code StreamProxyValuesBackendSet} class.
 */
public class StreamProxyValuesBackendSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the class in which only a single backend
   * server is available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleBackendServer()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "directory.example.com" },
         new int[] { 389 });
    s = StreamProxyValuesBackendSet.decode(s.encode());

    assertNotNull(s);

    assertEquals(s.getBackendSetID().stringValue(), "foo");

    assertNotNull(s.getHosts());
    assertEquals(s.getHosts().length, 1);
    assertEquals(s.getHosts()[0], "directory.example.com");

    assertNotNull(s.getPorts());
    assertEquals(s.getPorts().length, 1);
    assertEquals(s.getPorts()[0], 389);

    assertNotNull(s.toString());
  }



  /**
   * Provides basic test coverage for the class when multiple backend servers
   * are available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleBackendServers()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("bar"),
         new String[] { "ds1.example.com", "ds2.example.com" },
         new int[] { 1389, 2389 });
    s = StreamProxyValuesBackendSet.decode(s.encode());

    assertNotNull(s);

    assertEquals(s.getBackendSetID().stringValue(), "bar");

    assertNotNull(s.getHosts());
    assertEquals(s.getHosts().length, 2);
    assertEquals(s.getHosts()[0], "ds1.example.com");
    assertEquals(s.getHosts()[1], "ds2.example.com");

    assertNotNull(s.getPorts());
    assertEquals(s.getPorts().length, 2);
    assertEquals(s.getPorts()[0], 1389);
    assertEquals(s.getPorts()[1], 2389);

    assertNotNull(s.toString());
  }



  /**
   * Verifies that it is not possible to create a backend set with a
   * {@code null} backend set ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullBackendSetID()
         throws Exception
  {
    new StreamProxyValuesBackendSet(null,
             new String[] { "directory.example.com" }, new int[] { 389 });
  }



  /**
   * Verifies that it is not possible to create a backend set with a
   * {@code null} set of hosts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullHosts()
         throws Exception
  {
    new StreamProxyValuesBackendSet(new ASN1OctetString("foo"), null,
             new int[] { 389 });
  }



  /**
   * Verifies that it is not possible to create a backend set with an empty set
   * of hosts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyHosts()
         throws Exception
  {
    new StreamProxyValuesBackendSet(new ASN1OctetString("foo"), new String[0],
             new int[] { 389 });
  }



  /**
   * Verifies that it is not possible to create a backend set with a
   * {@code null} set of ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullPorts()
         throws Exception
  {
    new StreamProxyValuesBackendSet(new ASN1OctetString("foo"),
             new String[] { "directory.example.com" }, null);
  }



  /**
   * Verifies that it is not possible to create a backend set with an empty set
   * of ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEmptyPorts()
         throws Exception
  {
    new StreamProxyValuesBackendSet(new ASN1OctetString("foo"),
             new String[] { "directory.example.com" }, new int[0]);
  }



  /**
   * Verifies that it is not possible to create a backend set with a mismatched
   * number of hosts and ports.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testMismatchedHostsAndPorts()
         throws Exception
  {
    new StreamProxyValuesBackendSet(new ASN1OctetString("foo"),
             new String[] { "ds1.example.com", "ds2.example.com" },
             new int[] { 389 });
  }



  /**
   * Tests the behavior when attempting to decode an invalid element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalid()
         throws Exception
  {
    StreamProxyValuesBackendSet.decode(new ASN1OctetString("foo"));
  }
}
