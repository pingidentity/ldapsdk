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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the list notification
 * subscriptions extended result.
 */
public final class ListNotificationSubscriptionsExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic coverage for a non-success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonSuccessResult()
         throws Exception
  {
    final String[] referralURLs =
    {
      "ldap://ds1.example.com/",
      "ldap://ds2.example.com/",
    };

    ListNotificationSubscriptionsExtendedResult r =
         new ListNotificationSubscriptionsExtendedResult(1,
              ResultCode.UNWILLING_TO_PERFORM, "diag", "dc=matched,dc=dn",
              referralURLs, null);

    r = new ListNotificationSubscriptionsExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);

    assertNotNull(r.getDiagnosticMessage());
    assertEquals(r.getDiagnosticMessage(), "diag");

    assertNotNull(r.getMatchedDN());
    assertDNsEqual(r.getMatchedDN(), "dc=matched,dc=dn");

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 2);

    assertNotNull(r.getDestinations());
    assertTrue(r.getDestinations().isEmpty());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Provides basic coverage for a success result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessResult()
         throws Exception
  {
    ListNotificationSubscriptionsExtendedResult r =
         new ListNotificationSubscriptionsExtendedResult(1, ResultCode.SUCCESS,
              null, null, null,
              Arrays.asList(
                   new NotificationDestinationDetails("dest-1",
                        Arrays.asList(new ASN1OctetString("detail-1")), null),
                   new NotificationDestinationDetails("dest-2",
                        Arrays.asList(
                             new ASN1OctetString("detail-2a"),
                             new ASN1OctetString("detail-2b")),
                        Arrays.asList(
                             new NotificationSubscriptionDetails("sub-1",
                                  Arrays.asList(
                                       new ASN1OctetString("detail-2s11"))),
                             new NotificationSubscriptionDetails("sub-2",
                                  Arrays.asList(
                                       new ASN1OctetString("detail-2s21"),
                                       new ASN1OctetString("detail-2s22")))))),
              new Control("1.2.3.4"), new Control("1.2.3.5", true));

    r = new ListNotificationSubscriptionsExtendedResult(r);

    assertNotNull(r.getResultCode());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    assertNull(r.getDiagnosticMessage());

    assertNull(r.getMatchedDN());

    assertNotNull(r.getReferralURLs());
    assertEquals(r.getReferralURLs().length, 0);

    assertNotNull(r.getDestinations());
    assertFalse(r.getDestinations().isEmpty());
    assertEquals(r.getDestinations().size(), 2);

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended result whose value
   * is not properly formed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new ListNotificationSubscriptionsExtendedResult(new ExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, "1.3.6.1.4.1.30221.2.6.41",
         new ASN1OctetString("malformed"), null));
  }
}
