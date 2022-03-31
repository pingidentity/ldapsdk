/*
 * Copyright 2019-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2022 Ping Identity Corporation
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
 * Copyright (C) 2019-2022 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the generate password response
 * control.
 */
public final class GeneratePasswordResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a response control that does not contain the
   * optional {@code secondsUntilExpiration} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithoutSecondsUntilExpiration()
         throws Exception
  {
    GeneratePasswordResponseControl c = new GeneratePasswordResponseControl(
         "the-generated-password", false, (Long) null);

    c = new GeneratePasswordResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.59");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getGeneratedPassword());
    assertEquals(c.getGeneratedPassword().stringValue(),
         "the-generated-password");

    assertNotNull(c.getGeneratedPasswordString());
    assertEquals(c.getGeneratedPasswordString(),
         "the-generated-password");

    assertNotNull(c.getGeneratedPasswordBytes());
    assertEquals(c.getGeneratedPasswordBytes(),
         StaticUtils.getBytes("the-generated-password"));

    assertFalse(c.mustChangePassword());

    assertNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a response control that includes the optional
   * optional {@code secondsUntilExpiration} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithSecondsUntilExpiration()
         throws Exception
  {
    GeneratePasswordResponseControl c = new GeneratePasswordResponseControl(
         StaticUtils.getBytes("another-generated-password"), true, 12345678L);

    c = new GeneratePasswordResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.59");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getGeneratedPassword());
    assertEquals(c.getGeneratedPassword().stringValue(),
         "another-generated-password");

    assertNotNull(c.getGeneratedPasswordString());
    assertEquals(c.getGeneratedPasswordString(),
         "another-generated-password");

    assertNotNull(c.getGeneratedPasswordBytes());
    assertEquals(c.getGeneratedPasswordBytes(),
         StaticUtils.getBytes("another-generated-password"));

    assertTrue(c.mustChangePassword());

    assertNotNull(c.getSecondsUntilExpiration());
    assertEquals(c.getSecondsUntilExpiration().longValue(),
         12345678L);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the {@code decodeControl} method for a control that
   * does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlMissingValue()
         throws Exception
  {
    new GeneratePasswordResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.59", false, null);
  }



  /**
   * Tests the behavior of the {@code decodeControl} method for a control that
   * has a value that cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithMalformedValue()
         throws Exception
  {
    new GeneratePasswordResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.59", false, new ASN1OctetString("foo"));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that does not include any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutAnyControls()
         throws Exception
  {
    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS);
    assertNull(GeneratePasswordResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that does includes controls but no generate password response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithNonGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.2.3.4", false, new ASN1OctetString("foo"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNull(GeneratePasswordResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate password response control that is
   * already an instance of that type of control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidDecodedGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new GeneratePasswordResponseControl("generated-password", true, 12345L)
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GeneratePasswordResponseControl.get(result));
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getGeneratedPasswordString(),
         "generated-password");
    assertTrue(
         GeneratePasswordResponseControl.get(result).mustChangePassword());
    assertNotNull(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration());
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration().longValue(),
         12345L);
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate password response control that is
   * provided as a generic control that needs to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidNonDecodedGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.59", false,
           new GeneratePasswordResponseControl("generated-password", true,
                12345L).getValue())
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GeneratePasswordResponseControl.get(result));
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getGeneratedPasswordString(),
         "generated-password");
    assertTrue(
         GeneratePasswordResponseControl.get(result).mustChangePassword());
    assertNotNull(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration());
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration().longValue(),
         12345L);
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that has a control with the same OID as the generate password
   * response control, but that cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithInvalidGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.59", false,
           new ASN1OctetString("foo"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    GeneratePasswordResponseControl.get(result);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the new password does not have an expiration time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoExpirationTime()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

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
    assertEquals(valueObject.getFields().size(), 2);

    assertEquals(valueObject.getFieldAsString("generated-password"),
         "TheGeneratedPassword");

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.FALSE);

    assertNull(valueObject.getFieldAsLong("seconds-until-expiration"));


    GeneratePasswordResponseControl decodedControl =
         GeneratePasswordResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());


    decodedControl =
         (GeneratePasswordResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the new password has an expiration time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithExpirationTime()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", true,
              1234567L);

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
    assertEquals(valueObject.getFields().size(), 3);

    assertEquals(valueObject.getFieldAsString("generated-password"),
         "TheGeneratedPassword");

    assertEquals(valueObject.getFieldAsBoolean("must-change-password"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsLong("seconds-until-expiration"),
         Long.valueOf(1234567L));


    GeneratePasswordResponseControl decodedControl =
         GeneratePasswordResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertTrue(decodedControl.mustChangePassword());

    assertEquals(decodedControl.getSecondsUntilExpiration(),
         Long.valueOf(1234567L));


    decodedControl =
         (GeneratePasswordResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertTrue(decodedControl.mustChangePassword());

    assertEquals(decodedControl.getSecondsUntilExpiration(),
         Long.valueOf(1234567L));
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
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GeneratePasswordResponseControl decodedControl =
         GeneratePasswordResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());


    decodedControl =
         (GeneratePasswordResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object is missing the generated-password field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingGeneratedPassword()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("must-change-password", false))));

    GeneratePasswordResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object is missing the must-change-password field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingMustChangePassword()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("generated-password", "TheGeneratedPassword"))));

    GeneratePasswordResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("generated-password", "TheGeneratedPassword"),
              new JSONField("must-change-password", false),
              new JSONField("unrecognized", "foo"))));

    GeneratePasswordResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final GeneratePasswordResponseControl c =
         new GeneratePasswordResponseControl("TheGeneratedPassword", false,
              (Long) null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("generated-password", "TheGeneratedPassword"),
              new JSONField("must-change-password", false),
              new JSONField("unrecognized", "foo"))));

    GeneratePasswordResponseControl decodedControl =
         GeneratePasswordResponseControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());


    decodedControl =
         (GeneratePasswordResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getGeneratedPasswordString(),
         "TheGeneratedPassword");

    assertFalse(decodedControl.mustChangePassword());

    assertNull(decodedControl.getSecondsUntilExpiration());
  }
}
