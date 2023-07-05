/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the
 * {@code AccessLogFieldRequestControl} class.
 */
public final class AccessLogFieldRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor with a single field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleField()
         throws Exception
  {
    AccessLogFieldRequestControl c = new AccessLogFieldRequestControl(
         new JSONField("field-name", "field-value"));

    c = new AccessLogFieldRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.66");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());
    assertEquals(new JSONObject(c.getValue().stringValue()),
         new JSONObject(new JSONField("field-name", "field-value")));

    assertNotNull(c.getControlName());

    assertNotNull(c.getFieldsObject());
    assertEquals(c.getFieldsObject(),
         new JSONObject(new JSONField("field-name", "field-value")));

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the default constructor with multiple fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleFields()
         throws Exception
  {
    AccessLogFieldRequestControl c = new AccessLogFieldRequestControl(true,
         new JSONField("boolean-field", true),
         new JSONField("number-field", 12345),
         new JSONField("string-field", "string-value"));

    c = new AccessLogFieldRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.66");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());
    assertEquals(new JSONObject(c.getValue().stringValue()),
         new JSONObject(new JSONField("boolean-field", true),
              new JSONField("number-field", 12345),
              new JSONField("string-field", "string-value")));

    assertNotNull(c.getControlName());

    assertNotNull(c.getFieldsObject());
    assertEquals(c.getFieldsObject(),
         new JSONObject(new JSONField("boolean-field", true),
              new JSONField("number-field", 12345),
              new JSONField("string-field", "string-value")));

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the default constructor with multiple fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testNoFields()
         throws Exception
  {
    new AccessLogFieldRequestControl(true);
  }



  /**
   * Provides test coverage for the default constructor with a field containing
   * an invalid name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFieldWithInvalidName()
         throws Exception
  {
    new AccessLogFieldRequestControl(
         new JSONField("valid-Field_Name-1", "this field has a valid name"),
         new JSONField("invalid field name", "this field has an invalid name"));
  }



  /**
   * Provides test coverage for the default constructor with a field containing
   * a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testNullField()
         throws Exception
  {
    new AccessLogFieldRequestControl(
         new JSONField("field-name", JSONNull.NULL));
  }



  /**
   * Provides test coverage for the default constructor with a field containing
   * an array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testArrayField()
         throws Exception
  {
    new AccessLogFieldRequestControl(
         new JSONField("field-name", new JSONArray(
              new JSONString("value-1"),
              new JSONString("value-2"))));
  }



  /**
   * Provides test coverage for the default constructor with a field containing
   * an object value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testObjectField()
         throws Exception
  {
    new AccessLogFieldRequestControl(
         new JSONField("top-level-field", new JSONObject(
              new JSONField("sub-field", "sub-field-value"))));
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.30221.2.5.66");
    new AccessLogFieldRequestControl(genericControl);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * valid JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotJSON()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.30221.2.5.66",
         false, new ASN1OctetString("foo"));
    new AccessLogFieldRequestControl(genericControl);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is an empty
   * JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueEmpty()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.30221.2.5.66",
         false, new ASN1OctetString(JSONObject.EMPTY_OBJECT.toString()));
    new AccessLogFieldRequestControl(genericControl);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControl()
          throws Exception
  {
    final AccessLogFieldRequestControl c = new AccessLogFieldRequestControl(
         new JSONField("field-name", "field-value"));

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality").booleanValue(),
         c.isCritical());

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject,
         new JSONObject(new JSONField("field-name", "field-value")));


    AccessLogFieldRequestControl decodedControl =
         AccessLogFieldRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFieldsObject(),
         new JSONObject(new JSONField("field-name", "field-value")));


    decodedControl =
         (AccessLogFieldRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFieldsObject(),
         new JSONObject(new JSONField("field-name", "field-value")));
  }



  /**
   * Tests the behavior when trying to decode a control from a JSON object when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final AccessLogFieldRequestControl c = new AccessLogFieldRequestControl(
         true, new JSONField("field-name", "field-value"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    AccessLogFieldRequestControl decodedControl =
         AccessLogFieldRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFieldsObject(),
         new JSONObject(new JSONField("field-name", "field-value")));


    decodedControl =
         (AccessLogFieldRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFieldsObject(),
         new JSONObject(new JSONField("field-name", "field-value")));
  }
}
