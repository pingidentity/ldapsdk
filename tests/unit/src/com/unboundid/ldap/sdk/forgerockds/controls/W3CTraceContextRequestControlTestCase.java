/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.forgerockds.controls;



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the W3C trace context request
 * control.
 */
public final class W3CTraceContextRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control that includes a trace state value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithTraceState()
         throws Exception
  {
    final String traceParent = UUID.randomUUID().toString();
    final String traceState = UUID.randomUUID().toString();

    W3CTraceContextRequestControl c =
         new W3CTraceContextRequestControl(traceParent, traceState);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNotNull(c.getTraceState());
    assertEquals(c.getTraceState(), traceState);

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());


    c = new W3CTraceContextRequestControl(new Control(c.getOID(),
         c.isCritical(), c.getValue()));

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNotNull(c.getTraceState());
    assertEquals(c.getTraceState(), traceState);

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());


    final JSONObject controlJSON = c.toJSONControl();
    assertNotNull(controlJSON);

    final Control decodedFromJSON =
         Control.decodeJSONControl(controlJSON, true, true);
    assertNotNull(decodedFromJSON);
    assertTrue(decodedFromJSON instanceof W3CTraceContextRequestControl);

    c = (W3CTraceContextRequestControl) decodedFromJSON;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNotNull(c.getTraceState());
    assertEquals(c.getTraceState(), traceState);

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that does not include a trace state value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithoutTraceState()
         throws Exception
  {
    final String traceParent = UUID.randomUUID().toString();

    W3CTraceContextRequestControl c =
         new W3CTraceContextRequestControl(traceParent, null, true);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNull(c.getTraceState());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());


    c = new W3CTraceContextRequestControl(new Control(c.getOID(),
         c.isCritical(), c.getValue()));

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNull(c.getTraceState());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());


    final JSONObject controlJSON = c.toJSONControl();
    assertNotNull(controlJSON);

    final Control decodedFromJSON =
         Control.decodeJSONControl(controlJSON, true, true);
    assertNotNull(decodedFromJSON);
    assertTrue(decodedFromJSON instanceof W3CTraceContextRequestControl);

    c = (W3CTraceContextRequestControl) decodedFromJSON;

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getTraceParent());
    assertEquals(c.getTraceParent(), traceParent);

    assertNull(c.getTraceState());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "W3C Trace Context Request Control");

    assertNotNull(c.toString());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to create an instance of the control without
   * a trace parent.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPSDKUsageException.class)
  public void testControlWithoutTraceParent()
         throws Exception
  {
    new W3CTraceContextRequestControl(null, UUID.randomUUID().toString());
  }



  /**
   * Tests the behavior when trying to decode a generic control that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new W3CTraceContextRequestControl(new Control("1.3.6.1.4.1.36733.2.1.5.7"));
  }



  /**
   * Tests the behavior when trying to decode a generic control with an invalid
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testDecodeControlWithInvalidValue()
         throws Exception
  {
    new W3CTraceContextRequestControl(new Control("1.3.6.1.4.1.36733.2.1.5.7",
         false, new ASN1OctetString("invalid value")));
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object
   * when the object includes a valid raw value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlWithValidRawValue()
         throws Exception
  {
    final String traceParent = UUID.randomUUID().toString();
    final String traceState = UUID.randomUUID().toString();

    final W3CTraceContextRequestControl initialControl =
         new W3CTraceContextRequestControl(traceParent, traceState);

    final byte[] initialControlValueBytes =
         initialControl.getValue().getValue();
    final JSONObject objectToDecode = new JSONObject(
         new JSONField("oid", initialControl.getOID()),
         new JSONField("criticality", initialControl.isCritical()),
         new JSONField("value-base64",
              Base64.encode(initialControlValueBytes)));

    final W3CTraceContextRequestControl decodedControl =
         W3CTraceContextRequestControl.decodeJSONControl(objectToDecode, true);
    assertNotNull(decodedControl);

    assertNotNull(decodedControl.getOID());
    assertEquals(decodedControl.getOID(), "1.3.6.1.4.1.36733.2.1.5.7");

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getTraceParent());
    assertEquals(decodedControl.getTraceParent(), traceParent);

    assertNotNull(decodedControl.getTraceState());
    assertEquals(decodedControl.getTraceState(), traceState);

    assertNotNull(decodedControl.getControlName());
    assertEquals(decodedControl.getControlName(),
         "W3C Trace Context Request Control");

    assertNotNull(decodedControl.toString());

    assertNotNull(decodedControl.toString());
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object
   * when the object includes an invalid raw value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testDecodeJSONControlWithInvalidRawValue()
         throws Exception
  {
    final JSONObject objectToDecode = new JSONObject(
         new JSONField("oid", "1.3.6.1.4.1.36733.2.1.5.7"),
         new JSONField("criticality", false),
         new JSONField("value-base64",
              Base64.encode("invalid-value")));

    W3CTraceContextRequestControl.decodeJSONControl(objectToDecode, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object
   * when the object is missing the required trace-parent field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testDecodeJSONControlWithMissingTraceParent()
         throws Exception
  {
    final JSONObject objectToDecode = new JSONObject(
         new JSONField("oid", "1.3.6.1.4.1.36733.2.1.5.7"),
         new JSONField("criticality", false),
         new JSONField("value-json",
              new JSONObject(
                   new JSONField("trace-state",
                        UUID.randomUUID().toString()))));

    W3CTraceContextRequestControl.decodeJSONControl(objectToDecode, true);
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object
   * when the object contains an unrecognized field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlWithUnrecognizedField()
         throws Exception
  {
    final String traceParent = UUID.randomUUID().toString();
    final String traceState = UUID.randomUUID().toString();

    // Create a JSON object that would be valid if it didn't have an
    // unrecognized field.
    final JSONObject objectToDecode = new JSONObject(
         new JSONField("oid", "1.3.6.1.4.1.36733.2.1.5.7"),
         new JSONField("criticality", false),
         new JSONField("value-json",
              new JSONObject(
                   new JSONField("trace-parent", traceParent),
                   new JSONField("trace-state", traceState),
                   new JSONField("unrecognized-field", "foo"))));


    // Make sure that we can successfully decode the object in non-strict mode.
    final W3CTraceContextRequestControl decodedControl =
         W3CTraceContextRequestControl.decodeJSONControl(objectToDecode, false);
    assertNotNull(decodedControl);

    assertNotNull(decodedControl.getTraceParent());
    assertEquals(decodedControl.getTraceParent(), traceParent);

    assertNotNull(decodedControl.getTraceState());
    assertEquals(decodedControl.getTraceState(), traceState);


    // Make sure that we cannot decode the control when operating in strict
    // mode.
    try
    {
      W3CTraceContextRequestControl.decodeJSONControl(objectToDecode, true);
      fail("Expected an exception when trying to decode a control from a " +
           "JSON object with an unrecognized field in strict mode.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }
}
