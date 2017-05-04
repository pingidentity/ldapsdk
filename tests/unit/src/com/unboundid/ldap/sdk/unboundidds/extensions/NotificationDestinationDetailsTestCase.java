/*
 * Copyright 2014-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2017 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the notification destination
 * details class.
 */
public final class NotificationDestinationDetailsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for a destination details object that does not have
   * any subscriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutSubscriptions()
         throws Exception
  {
    final NotificationDestinationDetails d =
         new NotificationDestinationDetails("test-destination-id",
              Arrays.asList(
                   new ASN1OctetString("details1"),
                   new ASN1OctetString("details2")),
              null);

    assertNotNull(d.getID());
    assertEquals(d.getID(), "test-destination-id");

    assertNotNull(d.getDetails());
    assertFalse(d.getDetails().isEmpty());
    assertEquals(d.getDetails().size(), 2);

    assertNotNull(d.getSubscriptions());
    assertTrue(d.getSubscriptions().isEmpty());

    assertNotNull(d.toString());
  }



  /**
   * Provides basic coverage for a destination details object that includes
   * subscriptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithSubscriptions()
         throws Exception
  {
    final NotificationDestinationDetails d =
         new NotificationDestinationDetails("test-destination-id",
              Arrays.asList(
                   new ASN1OctetString("details1"),
                   new ASN1OctetString("details2")),
              Arrays.asList(
                   new NotificationSubscriptionDetails("test-sub-id-1",
                        Arrays.asList(
                             new ASN1OctetString("sub1d1"))),
                   new NotificationSubscriptionDetails("test-sub-id-2",
                        Arrays.asList(
                             new ASN1OctetString("sub2d1"),
                             new ASN1OctetString("sub2d2")))));

    assertNotNull(d.getID());
    assertEquals(d.getID(), "test-destination-id");

    assertNotNull(d.getDetails());
    assertFalse(d.getDetails().isEmpty());
    assertEquals(d.getDetails().size(), 2);

    assertNotNull(d.getSubscriptions());
    assertFalse(d.getSubscriptions().isEmpty());
    assertEquals(d.getSubscriptions().size(), 2);

    assertNotNull(d.toString());
  }
}
