/*
 * Copyright 2014-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2025 Ping Identity Corporation
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
 * Copyright (C) 2014-2025 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the list notification
 * subscriptions extended request.
 */
public final class ListNotificationSubscriptionsExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for the extended request without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutControls()
         throws Exception
  {
    ListNotificationSubscriptionsExtendedRequest r =
         new ListNotificationSubscriptionsExtendedRequest("test-manager-id");

    r = new ListNotificationSubscriptionsExtendedRequest(r);

    r = r.duplicate();

    assertNotNull(r.getManagerID());
    assertEquals(r.getManagerID(), "test-manager-id");

    assertNotNull(r.getDestinationIDs());
    assertTrue(r.getDestinationIDs().isEmpty());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides basic coverage for the extended request with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithControls()
         throws Exception
  {
    ListNotificationSubscriptionsExtendedRequest r =
         new ListNotificationSubscriptionsExtendedRequest("test-manager-id",
              Arrays.asList("test-dest-id-1", "test-dest-id-2"),
              new Control("1.2.3.4"), new Control("1.2.3.5", true));

    r = new ListNotificationSubscriptionsExtendedRequest(r);

    r = r.duplicate();

    assertNotNull(r.getManagerID());
    assertEquals(r.getManagerID(), "test-manager-id");

    assertNotNull(r.getDestinationIDs());
    assertFalse(r.getDestinationIDs().isEmpty());
    assertEquals(r.getDestinationIDs().size(), 2);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new ListNotificationSubscriptionsExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.40"));
  }



  /**
   * Tests the behavior when trying to decode an extended request whose value
   * is not properly formed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new ListNotificationSubscriptionsExtendedRequest(
         new ExtendedRequest("1.3.6.1.4.1.30221.2.6.40",
              new ASN1OctetString("malformed")));
  }



  /**
   * Tests the behavior of the LDAP SDK when trying to invoke the operation in
   * the in-memory server.  The attempt will return a non-success result because
   * the in-memory server does not support the operation, but this will at least
   * get coverage for the affected client-side code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeOperation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    try
    {
      conn.processExtendedOperation(
           new ListNotificationSubscriptionsExtendedRequest("test-manager-id"));
    }
    catch (final Exception e)
    {
      // We don't really care whether this happens or not.
    }

    conn.close();
  }
}
