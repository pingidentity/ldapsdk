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



import java.util.Date;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the generate access token
 * response control.
 */
public final class GenerateAccessTokenResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control that does not have values for any of the
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithoutAnyElements()
         throws Exception
  {
    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, null);

    c = new GenerateAccessTokenResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.68");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNull(c.getErrorMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that has an access token and an expiration
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithAccessTokenAndExpirationTime()
         throws Exception
  {
    final String accessToken = UUID.randomUUID().toString();
    final Date expirationTime = new Date();

    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(accessToken, expirationTime,
              null);

    c = new GenerateAccessTokenResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.68");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getAccessToken());
    assertEquals(c.getAccessToken(), accessToken);

    assertNotNull(c.getExpirationTime());
    assertEquals(c.getExpirationTime(), expirationTime);

    assertNull(c.getErrorMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control that has an error message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithErrorMessage()
         throws Exception
  {
    final String errorMessage = "I didn't feel like generating a token.";

    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, errorMessage);

    c = new GenerateAccessTokenResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.68");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNotNull(c.getErrorMessage());
    assertEquals(c.getErrorMessage(), errorMessage);

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
    new GenerateAccessTokenResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.68", false, null);
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
    new GenerateAccessTokenResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.68", false, new ASN1OctetString("foo"));
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
    final BindResult result = new BindResult(1, ResultCode.SUCCESS, null,
         null, null, null);
    assertNull(GenerateAccessTokenResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that does includes controls but no generate access token response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithNonGenerateAccessTokenResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.2.3.4", false, new ASN1OctetString("foo"))
    };

    final BindResult result = new BindResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNull(GenerateAccessTokenResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate access token response control that is
   * already an instance of that type of control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidDecodedGenerateAccessTokenResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new GenerateAccessTokenResponseControl("the-access-token", null, null)
    };

    final BindResult result = new BindResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GenerateAccessTokenResponseControl.get(result));
    assertEquals(
         GenerateAccessTokenResponseControl.get(result).getAccessToken(),
         "the-access-token");
    assertNull(GenerateAccessTokenResponseControl.get(result).
         getExpirationTime());
    assertNull(GenerateAccessTokenResponseControl.get(result).
         getErrorMessage());
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate access token response control that is
   * provided as a generic control that needs to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidNonDecodedGenerateAccessTokenResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.68", false,
           new GenerateAccessTokenResponseControl("the-access-token", null,
                null).getValue())
    };

    final BindResult result = new BindResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GenerateAccessTokenResponseControl.get(result));
    assertEquals(
         GenerateAccessTokenResponseControl.get(result).getAccessToken(),
         "the-access-token");
    assertNull(GenerateAccessTokenResponseControl.get(result).
         getExpirationTime());
    assertNull(GenerateAccessTokenResponseControl.get(result).
         getErrorMessage());
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that has a control with the same OID as the generate access token
   * response control, but that cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithInvalidGenerateAccessTokenResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.68", false,
           new ASN1OctetString("foo"))
    };

    final BindResult result = new BindResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    GenerateAccessTokenResponseControl.get(result);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when none of the elements are present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoElements()
          throws Exception
  {
    final GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, null);

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
    assertTrue(valueObject.getFields().isEmpty());


    GenerateAccessTokenResponseControl decodedControl =
         GenerateAccessTokenResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNull(c.getErrorMessage());


    decodedControl =
         (GenerateAccessTokenResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNull(c.getErrorMessage());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the access token and expiration time elements are
   * present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAccessTokenAndExpirationTime()
          throws Exception
  {
    final String accessToken = UUID.randomUUID().toString();
    final Date expirationTime = new Date();

    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(accessToken, expirationTime,
              null);

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

    assertEquals(valueObject.getFieldAsString("token"), accessToken);

    assertEquals(valueObject.getFieldAsString("expiration-time"),
         StaticUtils.encodeRFC3339Time(expirationTime));

    assertNull(valueObject.getFieldAsString("error-messages"));


    GenerateAccessTokenResponseControl decodedControl =
         GenerateAccessTokenResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAccessToken(), accessToken);

    assertEquals(decodedControl.getExpirationTime(), expirationTime);

    assertNull(decodedControl.getErrorMessage());


    decodedControl =
         (GenerateAccessTokenResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAccessToken(), accessToken);

    assertEquals(decodedControl.getExpirationTime(), expirationTime);

    assertNull(decodedControl.getErrorMessage());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the error message element is present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithErrorMessage()
          throws Exception
  {
    final String errorMessage = "This is the error message.";

    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, errorMessage);

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

    assertNull(valueObject.getFieldAsString("token"));

    assertNull(valueObject.getFieldAsString("expiration-time"));

    assertEquals(valueObject.getFieldAsString("error-message"), errorMessage);


    GenerateAccessTokenResponseControl decodedControl =
         GenerateAccessTokenResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getAccessToken());

    assertNull(decodedControl.getExpirationTime());

    assertEquals(decodedControl.getErrorMessage(), errorMessage);


    decodedControl =
         (GenerateAccessTokenResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getAccessToken());

    assertNull(decodedControl.getExpirationTime());

    assertEquals(decodedControl.getErrorMessage(), errorMessage);
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
    final String accessToken = UUID.randomUUID().toString();
    final Date expirationTime = new Date();

    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(accessToken, expirationTime,
              null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GenerateAccessTokenResponseControl decodedControl =
         GenerateAccessTokenResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAccessToken(), accessToken);

    assertEquals(decodedControl.getExpirationTime(), expirationTime);

    assertNull(decodedControl.getErrorMessage());


    decodedControl =
         (GenerateAccessTokenResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAccessToken(), accessToken);

    assertEquals(decodedControl.getExpirationTime(), expirationTime);

    assertNull(decodedControl.getErrorMessage());
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
    GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("unrecognized", "foo"))));

    GenerateAccessTokenResponseControl.decodeJSONControl(controlObject, true);
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
    final GenerateAccessTokenResponseControl c =
         new GenerateAccessTokenResponseControl(null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("unrecognized", "foo"))));

    GenerateAccessTokenResponseControl decodedControl =
         GenerateAccessTokenResponseControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNull(c.getErrorMessage());


    decodedControl =
         (GenerateAccessTokenResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(c.getAccessToken());

    assertNull(c.getExpirationTime());

    assertNull(c.getErrorMessage());
  }
}
