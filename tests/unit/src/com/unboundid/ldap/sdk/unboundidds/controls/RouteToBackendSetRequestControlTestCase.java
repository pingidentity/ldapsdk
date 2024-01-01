/*
 * Copyright 2014-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2024 Ping Identity Corporation
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
 * Copyright (C) 2014-2024 Ping Identity Corporation
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
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



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



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when using absolute routing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAbsoluteRouting()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(true,
              "rpID", "bs1");

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "absolute-routing"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1")))));


    RouteToBackendSetRequestControl decodedControl =
         RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertEquals(decodedControl.getAbsoluteBackendSetIDs(),
         StaticUtils.setOf("bs1"));

    assertNull(decodedControl.getRoutingHintFirstGuessSetIDs());

    assertNull(decodedControl.getRoutingHintFallbackSetIDs());


    decodedControl =
         (RouteToBackendSetRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertEquals(decodedControl.getAbsoluteBackendSetIDs(),
         StaticUtils.setOf("bs1"));

    assertNull(decodedControl.getRoutingHintFirstGuessSetIDs());

    assertNull(decodedControl.getRoutingHintFallbackSetIDs());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when using a routing hint.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlRoutingHint()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4")))));


    RouteToBackendSetRequestControl decodedControl =
         RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(decodedControl.getAbsoluteBackendSetIDs());

    assertEquals(decodedControl.getRoutingHintFirstGuessSetIDs(),
         StaticUtils.setOf("bs1", "bs2"));

    assertEquals(decodedControl.getRoutingHintFallbackSetIDs(),
         StaticUtils.setOf("bs3", "bs4"));


    decodedControl =
         (RouteToBackendSetRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(decodedControl.getAbsoluteBackendSetIDs());

    assertEquals(decodedControl.getRoutingHintFirstGuessSetIDs(),
         StaticUtils.setOf("bs1", "bs2"));

    assertEquals(decodedControl.getRoutingHintFallbackSetIDs(),
         StaticUtils.setOf("bs3", "bs4"));
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createAbsoluteRoutingRequest(true,
              "rpID", "bs1");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    RouteToBackendSetRequestControl decodedControl =
         RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertEquals(decodedControl.getAbsoluteBackendSetIDs(),
         StaticUtils.setOf("bs1"));

    assertNull(decodedControl.getRoutingHintFirstGuessSetIDs());

    assertNull(decodedControl.getRoutingHintFallbackSetIDs());


    decodedControl =
         (RouteToBackendSetRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING);

    assertEquals(decodedControl.getAbsoluteBackendSetIDs(),
         StaticUtils.setOf("bs1"));

    assertNull(decodedControl.getRoutingHintFirstGuessSetIDs());

    assertNull(decodedControl.getRoutingHintFallbackSetIDs());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the required request-processor element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingRequestProcessor()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the required routing-type element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingRoutingType()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized routing type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedRoutingType()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "unrecognized"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the backend-set-ids element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingBackendSetIDs()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an empty set of backend IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueEmptyBackendSetIDs()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", JSONArray.EMPTY_ARRAY),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a backend-set-ids value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueBackendSetIDNotString()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a fallback-backend-set-ids value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueFallbackBackendSetIDNotString()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a fallback-backend-set-ids value when it is configured to
   * use absolute routing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueAbsoluteRoutingWithFallbackSetIDs()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "absolute-routing"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))),
              new JSONField("unrecognized", "foo"))));

    RouteToBackendSetRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final RouteToBackendSetRequestControl c =
         RouteToBackendSetRequestControl.createRoutingHintRequest(false,
              "rpID", StaticUtils.setOf("bs1", "bs2"),
              StaticUtils.setOf("bs3", "bs4"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("request-processor", "rpID"),
              new JSONField("routing-type", "routing-hint"),
              new JSONField("backend-set-ids", new JSONArray(
                   new JSONString("bs1"),
                   new JSONString("bs2"))),
              new JSONField("fallback-backend-set-ids", new JSONArray(
                   new JSONString("bs3"),
                   new JSONString("bs4"))),
              new JSONField("unrecognized", "foo"))));


    RouteToBackendSetRequestControl decodedControl =
         RouteToBackendSetRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(decodedControl.getAbsoluteBackendSetIDs());

    assertEquals(decodedControl.getRoutingHintFirstGuessSetIDs(),
         StaticUtils.setOf("bs1", "bs2"));

    assertEquals(decodedControl.getRoutingHintFallbackSetIDs(),
         StaticUtils.setOf("bs3", "bs4"));


    decodedControl =
         (RouteToBackendSetRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getEntryBalancingRequestProcessorID(), "rpID");

    assertEquals(decodedControl.getRoutingType(),
         RouteToBackendSetRoutingType.ROUTING_HINT);

    assertNull(decodedControl.getAbsoluteBackendSetIDs());

    assertEquals(decodedControl.getRoutingHintFirstGuessSetIDs(),
         StaticUtils.setOf("bs1", "bs2"));

    assertEquals(decodedControl.getRoutingHintFallbackSetIDs(),
         StaticUtils.setOf("bs3", "bs4"));
  }
}
