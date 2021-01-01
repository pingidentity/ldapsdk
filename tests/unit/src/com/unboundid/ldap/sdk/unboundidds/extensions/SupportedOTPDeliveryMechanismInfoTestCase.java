/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@code SupportedOTPDeliveryMechanismInfo} class.
 */
public final class SupportedOTPDeliveryMechanismInfoTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a supported mechanism with a recipient ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSupportedMechanismWithRecipientID()
         throws Exception
  {
    final SupportedOTPDeliveryMechanismInfo i =
         new SupportedOTPDeliveryMechanismInfo("email", true,
              "john.doe@example.com");

    assertNotNull(i.getDeliveryMechanism());
    assertEquals(i.getDeliveryMechanism(), "email");

    assertNotNull(i.isSupported());
    assertEquals(i.isSupported(), Boolean.TRUE);

    assertNotNull(i.getRecipientID());
    assertEquals(i.getRecipientID(), "john.doe@example.com");

    assertNotNull(i.toString());

    assertTrue(i.equals(i));
    assertEquals(i.hashCode(), i.hashCode());

    assertFalse(i.equals(null));

    assertFalse(i.equals("foo"));

    assertTrue(i.equals(new SupportedOTPDeliveryMechanismInfo("email", true,
         "john.doe@example.com")));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo("Email", true,
         "john.doe@example.com")));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo("email", false,
         "john.doe@example.com")));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo("email", null,
         "john.doe@example.com")));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo("email", true,
         null)));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo("email", true,
         "jane.doe@example.com")));
  }



  /**
   * Tests the behavior for a supported mechanism without a recipient ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSupportedMechanismWithoutRecipientID()
         throws Exception
  {
    final SupportedOTPDeliveryMechanismInfo i =
         new SupportedOTPDeliveryMechanismInfo("mental-telepathy", true, null);

    assertNotNull(i.getDeliveryMechanism());
    assertEquals(i.getDeliveryMechanism(), "mental-telepathy");

    assertNotNull(i.isSupported());
    assertEquals(i.isSupported(), Boolean.TRUE);

    assertNull(i.getRecipientID());

    assertNotNull(i.toString());

    assertTrue(i.equals(i));
    assertEquals(i.hashCode(), i.hashCode());

    assertFalse(i.equals(null));

    assertFalse(i.equals("foo"));

    assertTrue(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "mental-telepathy", true, null)));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "Mental-Telepathy", true, null)));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "mental-telepathy", false, null)));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "mental-telepathy", null, null)));
    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "mental-telepathy", true, "brainwaves")));
  }



  /**
   * Tests the behavior for a non-supported mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonSupportedMechanism()
         throws Exception
  {
    final SupportedOTPDeliveryMechanismInfo i =
         new SupportedOTPDeliveryMechanismInfo("SMS", false, null);

    assertNotNull(i.getDeliveryMechanism());
    assertEquals(i.getDeliveryMechanism(), "SMS");

    assertNotNull(i.isSupported());
    assertEquals(i.isSupported(), Boolean.FALSE);

    assertNull(i.getRecipientID());

    assertNotNull(i.toString());

    assertTrue(i.equals(i));
    assertEquals(i.hashCode(), i.hashCode());

    assertFalse(i.equals(null));

    assertFalse(i.equals("foo"));

    assertTrue(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "SMS", false, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "Text Message", false, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "SMS", true, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "SMS", null, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "SMS", false, "123-456-7890")));
  }



  /**
   * Tests the behavior for a mechanism whose support is unknown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnknownSupportedMechanism()
         throws Exception
  {
    final SupportedOTPDeliveryMechanismInfo i =
         new SupportedOTPDeliveryMechanismInfo("cans-and-string", null, null);

    assertNotNull(i.getDeliveryMechanism());
    assertEquals(i.getDeliveryMechanism(), "cans-and-string");

    assertNull(i.isSupported());

    assertNull(i.getRecipientID());

    assertNotNull(i.toString());

    assertTrue(i.equals(i));
    assertEquals(i.hashCode(), i.hashCode());

    assertFalse(i.equals(null));

    assertFalse(i.equals("foo"));

    assertTrue(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "cans-and-string", null, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "Cans and String", null, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "cans-and-string", true, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "cans-and-string", false, null)));

    assertFalse(i.equals(new SupportedOTPDeliveryMechanismInfo(
         "cans-and-string", null, "tin and twine")));
  }
}
