/*
 * Copyright 2011-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2025 Ping Identity Corporation
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
 * Copyright (C) 2011-2025 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the operation purpose request
 * control.
 */
public final class OperationPurposeRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests control behavior with an automatically-generated code location and
   * all other elements present in the control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllGeneratedCodeLocation()
         throws Exception
  {
    OperationPurposeRequestControl c = new OperationPurposeRequestControl(
         Version.SHORT_NAME, Version.SHORT_VERSION_STRING, 5,
         "Test from testAllGeneratedCodeLocation");
    c = new OperationPurposeRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getApplicationName());
    assertEquals(c.getApplicationName(), Version.SHORT_NAME);

    assertNotNull(c.getApplicationVersion());
    assertEquals(c.getApplicationVersion(), Version.SHORT_VERSION_STRING);

    assertNotNull(c.getCodeLocation());
    assertTrue(c.getCodeLocation().length() > 0);

    assertNotNull(c.getRequestPurpose());
    assertEquals(c.getRequestPurpose(),
         "Test from testAllGeneratedCodeLocation");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests control behavior with an explicitly-provided code location and
   * all other elements present in the control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllExplicitCodeLocation()
         throws Exception
  {
    OperationPurposeRequestControl c = new OperationPurposeRequestControl(
         false, Version.SHORT_NAME, Version.SHORT_VERSION_STRING,
         "OperationPurposeRequestControlTestCase.testAllExplicitCodeLocation",
         "Test from testAllExplicitCodeLocation");
    c = new OperationPurposeRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getApplicationName());
    assertEquals(c.getApplicationName(), Version.SHORT_NAME);

    assertNotNull(c.getApplicationVersion());
    assertEquals(c.getApplicationVersion(), Version.SHORT_VERSION_STRING);

    assertNotNull(c.getCodeLocation());
    assertEquals(c.getCodeLocation(),
         "OperationPurposeRequestControlTestCase.testAllExplicitCodeLocation");

    assertNotNull(c.getRequestPurpose());
    assertEquals(c.getRequestPurpose(),
         "Test from testAllExplicitCodeLocation");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests control behavior without an automatically-generated code location
   * and all other elements present in the control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllNullCodeLocation()
         throws Exception
  {
    OperationPurposeRequestControl c = new OperationPurposeRequestControl(
         false, Version.SHORT_NAME, Version.SHORT_VERSION_STRING, null,
         "Test from testAllNullCodeLocation");
    c = new OperationPurposeRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getApplicationName());
    assertEquals(c.getApplicationName(), Version.SHORT_NAME);

    assertNotNull(c.getApplicationVersion());
    assertEquals(c.getApplicationVersion(), Version.SHORT_VERSION_STRING);

    assertNull(c.getCodeLocation());

    assertNotNull(c.getRequestPurpose());
    assertEquals(c.getRequestPurpose(),
         "Test from testAllNullCodeLocation");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests control behavior when a generated code ID is the only element
   * included in the request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyGeneratedCodeLocation()
         throws Exception
  {
    OperationPurposeRequestControl c = new OperationPurposeRequestControl(
         null, null, 0, null);
    c = new OperationPurposeRequestControl(c);

    assertNotNull(c);

    assertNull(c.getApplicationName());

    assertNull(c.getApplicationVersion());

    assertNotNull(c.getCodeLocation());
    assertTrue(c.getCodeLocation().length() > 0);

    assertNull(c.getRequestPurpose());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests control behavior when a request purpose is the only element
   * included in the request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyPurpose()
         throws Exception
  {
    OperationPurposeRequestControl c = new OperationPurposeRequestControl(
         false, null, null, null, "Test from testOnlyPurpose");
    c = new OperationPurposeRequestControl(c);

    assertNotNull(c);

    assertNull(c.getApplicationName());

    assertNull(c.getApplicationVersion());

    assertNull(c.getCodeLocation());

    assertNotNull(c.getRequestPurpose());
    assertEquals(c.getRequestPurpose(),
         "Test from testOnlyPurpose");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to create a control without any elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNoElements()
         throws Exception
  {
    new OperationPurposeRequestControl(false, null, null, null, null);
  }



  /**
   * Tests the behavior when trying to decode a control that does not contain a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    final Control c = new Control(
         OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID,
         false, null);
    new OperationPurposeRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not an
   * ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    final Control c = new Control(
         OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID,
         false, new ASN1OctetString("foo"));
    new OperationPurposeRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is an
   * empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    final Control c = new Control(
         OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID,
         false, new ASN1OctetString(new ASN1Sequence().encode()));
    new OperationPurposeRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidElementType()
         throws Exception
  {
    final Control c = new Control(
         OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID,
         false, new ASN1OctetString(
              new ASN1Sequence(new ASN1OctetString("foo")).encode()));
    new OperationPurposeRequestControl(c);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the value only has a request purpose.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlOnlyRequestPurpose()
          throws Exception
  {
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(false, null, null, null,
              "TheRequestPurpose");

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
              new JSONField("request-purpose", "TheRequestPurpose")));


    OperationPurposeRequestControl decodedControl =
         OperationPurposeRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getApplicationName());

    assertNull(decodedControl.getApplicationVersion());

    assertNull(decodedControl.getCodeLocation());

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");


    decodedControl =
         (OperationPurposeRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getApplicationName());

    assertNull(decodedControl.getApplicationVersion());

    assertNull(decodedControl.getCodeLocation());

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the value includes all fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllFields()
          throws Exception
  {
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(true,
              "TheApplicationName", "TheApplicationVersion", "TheCodeLocation",
              "TheRequestPurpose");

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
              new JSONField("application-name", "TheApplicationName"),
              new JSONField("application-version", "TheApplicationVersion"),
              new JSONField("code-location", "TheCodeLocation"),
              new JSONField("request-purpose", "TheRequestPurpose")));


    OperationPurposeRequestControl decodedControl =
         OperationPurposeRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");


    decodedControl =
         (OperationPurposeRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");
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
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(true,
              "TheApplicationName", "TheApplicationVersion", "TheCodeLocation",
              "TheRequestPurpose");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    OperationPurposeRequestControl decodedControl =
         OperationPurposeRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");


    decodedControl =
         (OperationPurposeRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is an empty object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueEmpty()
          throws Exception
  {
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(true,
              "TheApplicationName", "TheApplicationVersion", "TheCodeLocation",
              "TheRequestPurpose");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json",
              JSONObject.EMPTY_OBJECT));


    OperationPurposeRequestControl.decodeJSONControl(controlObject, true);
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
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(true,
              "TheApplicationName", "TheApplicationVersion", "TheCodeLocation",
              "TheRequestPurpose");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("application-name", "TheApplicationName"),
              new JSONField("application-version", "TheApplicationVersion"),
              new JSONField("code-location", "TheCodeLocation"),
              new JSONField("request-purpose", "TheRequestPurpose"),
              new JSONField("unrecognized", "foo"))));


    OperationPurposeRequestControl.decodeJSONControl(controlObject, true);
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
    final OperationPurposeRequestControl c =
         new OperationPurposeRequestControl(true,
              "TheApplicationName", "TheApplicationVersion", "TheCodeLocation",
              "TheRequestPurpose");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("application-name", "TheApplicationName"),
              new JSONField("application-version", "TheApplicationVersion"),
              new JSONField("code-location", "TheCodeLocation"),
              new JSONField("request-purpose", "TheRequestPurpose"),
              new JSONField("unrecognized", "foo"))));


    OperationPurposeRequestControl decodedControl =
         OperationPurposeRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");


    decodedControl =
         (OperationPurposeRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getApplicationName(), "TheApplicationName");

    assertEquals(decodedControl.getApplicationVersion(),
         "TheApplicationVersion");

    assertEquals(decodedControl.getCodeLocation(), "TheCodeLocation");

    assertEquals(decodedControl.getRequestPurpose(), "TheRequestPurpose");
  }
}
