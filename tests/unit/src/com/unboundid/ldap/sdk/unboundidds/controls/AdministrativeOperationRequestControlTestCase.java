/*
 * Copyright 2009-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2024 Ping Identity Corporation
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
 * Copyright (C) 2009-2024 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides test coverage for the
 * {@code AdministrativeOperationRequestControl} class.
 */
public class AdministrativeOperationRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which does not take any
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl();
    c = new AdministrativeOperationRequestControl(c);

    assertNotNull(c);

    assertNull(c.getMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a string argument
   * with a non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNonNullString()
         throws Exception
  {
    AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl("foo");
    c = new AdministrativeOperationRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getMessage());
    assertEquals(c.getMessage(), "foo");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a string argument
   * with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNullString()
         throws Exception
  {
    AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl((String) null);
    c = new AdministrativeOperationRequestControl(c);

    assertNotNull(c);

    assertNull(c.getMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is no message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutMessage()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl();

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

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject, JSONObject.EMPTY_OBJECT);


    AdministrativeOperationRequestControl decodedControl =
         AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getMessage());


    decodedControl =
         (AdministrativeOperationRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getMessage());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithMessage()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl("foo");

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

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 1);


    AdministrativeOperationRequestControl decodedControl =
         AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");


    decodedControl =
         (AdministrativeOperationRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");
  }



  /**
   * Tests the behavior when trying to decode a control when there is no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlNoValue()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl();

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()));

    AdministrativeOperationRequestControl decodedControl =
         AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getMessage());


    decodedControl =
         (AdministrativeOperationRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getMessage());
  }



  /**
   * Tests the behavior when trying to decode a control when the value is
   * provided in a base64-encoded representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl("foo");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));

    AdministrativeOperationRequestControl decodedControl =
         AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");


    decodedControl =
         (AdministrativeOperationRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");
  }



  /**
   * Tests the behavior when trying to decode a control when the value contains
   * an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrictMode()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl("foo");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("message", "foo"),
              new JSONField("unrecognized", "bar"))));

    AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
         true);
  }



  /**
   * Tests the behavior when trying to decode a control when the value contains
   * an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrictMode()
          throws Exception
  {
    final AdministrativeOperationRequestControl c =
         new AdministrativeOperationRequestControl("foo");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("message", "foo"),
              new JSONField("unrecognized", "bar"))));

    AdministrativeOperationRequestControl decodedControl =
         AdministrativeOperationRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");


    decodedControl =
         (AdministrativeOperationRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getMessage(), "foo");
  }
}
