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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the route to backend set request
 * control.
 */
public final class RouteToBackendSetRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for an absolute routing request with a single
   * backend set ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbsoluteRoutingSingleSet()
         throws Exception
  {
    RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(
              true, "eb-id", "bs-id");
    c = new RouteToBackendSetRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.35");
    assertEquals(c.getOID(),
         RouteToBackendSetRequestControl.ROUTE_TO_BACKEND_SET_REQUEST_OID);

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getRoutingType());
    assertEquals(c.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertNotNull(c.getAbsoluteBackendSetIDs());
    assertFalse(c.getAbsoluteBackendSetIDs().isEmpty());
    assertEquals(c.getAbsoluteBackendSetIDs().size(), 1);
    assertTrue(c.getAbsoluteBackendSetIDs().contains("bs-id"));

    assertNull(c.getRoutingHintFirstGuessSetIDs());

    assertNull(c.getRoutingHintFallbackSetIDs());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for an absolute routing request with multiple
   * target sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbsoluteRoutingMultipleSets()
         throws Exception
  {
    RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(
              false, "eb-id", Arrays.asList("bs-id-1", "bs-id-2"));
    c = new RouteToBackendSetRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.35");
    assertEquals(c.getOID(),
         RouteToBackendSetRequestControl.ROUTE_TO_BACKEND_SET_REQUEST_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getRoutingType());
    assertEquals(c.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertNotNull(c.getAbsoluteBackendSetIDs());
    assertFalse(c.getAbsoluteBackendSetIDs().isEmpty());
    assertEquals(c.getAbsoluteBackendSetIDs().size(), 2);
    assertTrue(c.getAbsoluteBackendSetIDs().contains("bs-id-1"));
    assertTrue(c.getAbsoluteBackendSetIDs().contains("bs-id-2"));

    assertNull(c.getRoutingHintFirstGuessSetIDs());

    assertNull(c.getRoutingHintFallbackSetIDs());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a routing hint request with a single hint
   * set ID and an unspecified group of fallback sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoutingHintSingleSet()
         throws Exception
  {
    RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(true,
              "eb-id", "first-guess-bs", null);
    c = new RouteToBackendSetRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.35");
    assertEquals(c.getOID(),
         RouteToBackendSetRequestControl.ROUTE_TO_BACKEND_SET_REQUEST_OID);

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getRoutingType());
    assertEquals(c.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(c.getAbsoluteBackendSetIDs());

    assertNotNull(c.getRoutingHintFirstGuessSetIDs());
    assertFalse(c.getRoutingHintFirstGuessSetIDs().isEmpty());
    assertEquals(c.getRoutingHintFirstGuessSetIDs().size(), 1);
    assertTrue(c.getRoutingHintFirstGuessSetIDs().contains("first-guess-bs"));

    assertNull(c.getRoutingHintFallbackSetIDs());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a routing hint request with a multiple hint set
   * IDs and multiple fallback set IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoutingHintMultipleSets()
         throws Exception
  {
    RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "eb-id", Arrays.asList("first-guess-bs-1", "first-guess-bs-2"),
              Arrays.asList("fallback-bs-1", "fallback-bs-2"));
    c = new RouteToBackendSetRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.35");
    assertEquals(c.getOID(),
         RouteToBackendSetRequestControl.ROUTE_TO_BACKEND_SET_REQUEST_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getEntryBalancingRequestProcessorID());
    assertEquals(c.getEntryBalancingRequestProcessorID(), "eb-id");

    assertNotNull(c.getRoutingType());
    assertEquals(c.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(c.getAbsoluteBackendSetIDs());

    assertNotNull(c.getRoutingHintFirstGuessSetIDs());
    assertFalse(c.getRoutingHintFirstGuessSetIDs().isEmpty());
    assertEquals(c.getRoutingHintFirstGuessSetIDs().size(), 2);
    assertTrue(c.getRoutingHintFirstGuessSetIDs().contains("first-guess-bs-1"));
    assertTrue(c.getRoutingHintFirstGuessSetIDs().contains("first-guess-bs-2"));

    assertNotNull(c.getRoutingHintFallbackSetIDs());
    assertFalse(c.getRoutingHintFallbackSetIDs().isEmpty());
    assertEquals(c.getRoutingHintFallbackSetIDs().size(), 2);
    assertTrue(c.getRoutingHintFallbackSetIDs().contains("fallback-bs-1"));
    assertTrue(c.getRoutingHintFallbackSetIDs().contains("fallback-bs-2"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the attempt to decode a control that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, null));
  }



  /**
   * Provides test coverage for the attempt to decode a control whose value
   * cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, new ASN1OctetString("foo")));
  }



  /**
   * Provides test coverage for the attempt to decode a control whose value
   * cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidRoutingType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("eb-set"),
         new ASN1OctetString((byte) 0x83, "foo"));

    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for the attempt to decode a control whose value
   * sequence contains an empty set of absolute backend set IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceEmptyAbsoluteSet()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("eb-set"),
         new ASN1Set((byte) 0xA0));

    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for the attempt to decode a control whose value
   * sequence contains an empty set of routing hint first guess set IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceEmptyFirstGuessSet()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("eb-set"),
         new ASN1Sequence((byte) 0xA1,
              new ASN1Set()));

    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for the attempt to decode a control whose value
   * sequence contains an empty set of routing hint fallback set IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceEmptyFallbackSet()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString("eb-set"),
         new ASN1Sequence((byte) 0xA1,
              new ASN1Set(new ASN1OctetString("first-guess-bs")),
              new ASN1Set()));

    new RouteToBackendSetRequestControl(new Control("1.3.6.1.4.1.30221.2.5.35",
         false, new ASN1OctetString(valueSequence.encode())));
  }
}
