/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.UUID;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code RouteToServerRequestControl} class.
 */
public class RouteToServerRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the control with a number of configurations.
   *
   * @param  isCritical                 Indicates whether the server should be
   *                                    critical.
   * @param  allowAlternate             The allow alternate value to use when
   *                                    creating the control.
   * @param  preferLocal                The prefer local value to use when
   *                                    creating the control.
   * @param  preferNonDegraded          The prefer non-degraded value to use
   *                                    when creating the control.
   * @param  expectedAllowAlternate     The allow alternate server value for the
   *                                    resulting control.
   * @param  expectedPreferLocal        The expected prefer local value for the
   *                                    resulting control.
   * @param  expectedPreferNonDegraded  The expected prefer non-degraded value
   *                                    for the resulting control.
   *
   * Tests the control with a configuration that will always allow alternate
   * servers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testConfigs")
  public void testAlwaysAllowAlternate(final boolean isCritical,
                                       final boolean allowAlternate,
                                       final boolean preferLocal,
                                       final boolean preferNonDegraded,
                                       final boolean expectedAllowAlternate,
                                       final boolean expectedPreferLocal,
                                       final boolean expectedPreferNonDegraded)
         throws Exception
  {
    final String serverID = UUID.randomUUID().toString();

    RouteToServerRequestControl c = new RouteToServerRequestControl(isCritical,
         serverID, allowAlternate, preferLocal, preferNonDegraded);
    c = new RouteToServerRequestControl(c);

    assertEquals(c.isCritical(), isCritical);

    assertNotNull(c.getServerID());
    assertEquals(c.getServerID(), serverID);

    assertEquals(c.allowAlternateServer(), expectedAllowAlternate);

    assertEquals(c.preferLocalServer(), expectedPreferLocal);

    assertEquals(c.preferNonDegradedServer(), expectedPreferNonDegraded);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Retrieves a set of configurations that may be used to test the control.
   *
   * @return  A set of configurations that may be used to test the control.
   */
  @DataProvider(name="testConfigs")
  public Object[][] getTestConfigs()
  {
    return new Object[][]
    {
      new Object[] { true, true, true, true, true, true, true },
      new Object[] { true, false, false, false, false, false, false },
      new Object[] { true, false, true, true, false, false, false },
      new Object[] { true, true, false, true, true, false, true },
      new Object[] { true, true, true, false, true, true, false },
      new Object[] { false, true, true, true, true, true, true },
      new Object[] { false, false, false, false, false, false, false },
      new Object[] { false, false, true, true, false, false, false },
      new Object[] { false, true, false, true, true, false, true },
      new Object[] { false, true, true, false, true, true, false },
    };
  }



  /**
   * Tests the ability to decode a control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true, null));
  }



  /**
   * Tests the ability to decode a control whose value is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString("foo")));
  }



  /**
   * Tests the ability to decode a control with an empty value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence();

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the ability to decode a control with a malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "foo"),
         new ASN1OctetString((byte) 0x81, "bar"));

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the ability to decode a control with a value sequence containing an
   * unexpected element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "foo"),
         new ASN1Boolean((byte) 0x82, true),
         new ASN1Boolean((byte) 0x00, true));

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }
}
