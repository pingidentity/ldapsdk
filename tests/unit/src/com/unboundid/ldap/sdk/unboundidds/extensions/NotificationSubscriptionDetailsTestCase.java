/*
 * Copyright 2014-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2020 Ping Identity Corporation
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
 * This class provides a set of test cases for the notification subscription
 * details class.
 */
public final class NotificationSubscriptionDetailsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for a subscription details object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    final NotificationSubscriptionDetails d =
         new NotificationSubscriptionDetails("test-subscription-id",
              Arrays.asList(new ASN1OctetString("details1"),
                   new ASN1OctetString("details2")));

    assertNotNull(d.getID());
    assertEquals(d.getID(), "test-subscription-id");

    assertNotNull(d.getDetails());
    assertFalse(d.getDetails().isEmpty());
    assertEquals(d.getDetails().size(), 2);

    assertNotNull(d.toString());
  }
}
