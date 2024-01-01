/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the JSON control decode helper
 * class.
 */
public final class JSONControlDecodeHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to decode a valid JSON-encoded control
   * that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidControlWithoutValue()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false));

    final JSONControlDecodeHelper control =
         new JSONControlDecodeHelper(controlObject, true, false, false);

    assertNotNull(control.getControlObject());
    assertEquals(control.getControlObject(), controlObject);

    assertEquals(control.getOID(), "1.2.3.4");

    assertFalse(control.getCriticality());

    assertNull(control.getRawValue());

    assertNull(control.getValueObject());

    assertNotNull(control.toString());


    // Make sure that the same object cannot be decoded when a value is
    // required.
    try
    {
      new JSONControlDecodeHelper(controlObject, true, true, true);
      fail("Expected an exception when trying to decode a control without a " +
           "value when one was required.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to decode a valid JSON-encoded control
   * that has a base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidControlWithBase64Value()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", true),
         new JSONField("value-base64", Base64.encode("foo")));

    final JSONControlDecodeHelper control =
         new JSONControlDecodeHelper(controlObject, true, true, true);

    assertNotNull(control.getControlObject());
    assertEquals(control.getControlObject(), controlObject);

    assertEquals(control.getOID(), "1.2.3.4");

    assertTrue(control.getCriticality());

    assertNotNull(control.getRawValue());
    assertEquals(control.getRawValue(), new ASN1OctetString("foo"));

    assertNull(control.getValueObject());

    assertNotNull(control.toString());


    // Make sure that the same object cannot be decoded when a value is
    // not allowed.
    try
    {
      new JSONControlDecodeHelper(controlObject, true, false, false);
      fail("Expected an exception when trying to decode a control with a " +
           "value when none was allowed.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to decode a valid JSON-encoded control
   * that has a JSON-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeValidControlWithJSONValue()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("foo", "bar"))));

    final JSONControlDecodeHelper control =
         new JSONControlDecodeHelper(controlObject, true, true, true);

    assertNotNull(control.getControlObject());
    assertEquals(control.getControlObject(), controlObject);

    assertEquals(control.getOID(), "1.2.3.4");

    assertFalse(control.getCriticality());

    assertNull(control.getRawValue());

    assertNotNull(control.getValueObject());
    assertEquals(control.getValueObject(),
        new JSONObject(new JSONField("foo", "bar")));

    assertNotNull(control.toString());


    // Make sure that the same object cannot be decoded when a value is
    // not allowed.
    try
    {
      new JSONControlDecodeHelper(controlObject, true, false, false);
      fail("Expected an exception when trying to decode a control with a " +
           "value when none was allowed.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control that does
   * not have an OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutOID()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("foo", "bar"))));

    new JSONControlDecodeHelper(controlObject, true, true, true);
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control that does
   * not have a criticality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutCriticality()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("value-json", new JSONObject(
              new JSONField("foo", "bar"))));

    new JSONControlDecodeHelper(controlObject, true, true, true);
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control that has both
   * base64-encoded and JSON-formatted values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithBase64AndJSONValues()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("value-base64", Base64.encode("foo")),
         new JSONField("value-json", new JSONObject(
              new JSONField("foo", "bar"))));

    new JSONControlDecodeHelper(controlObject, true, true, true);
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control that has a
   * base64-encoded value that isn't valid base64.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithMalformedBase64Value()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("value-base64", "this is not valid base64"));

    new JSONControlDecodeHelper(controlObject, true, true, true);
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control with an
   * unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithUnrecognizedFieldStrictMode()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("unrecognized", "unrecognized"));

    new JSONControlDecodeHelper(controlObject, true, true, false);
  }



  /**
   * Tests the behavior when trying to decode JSON-encoded control with an
   * unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlWithUnrecognizedFieldNonStrictMode()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("unrecognized", "unrecognized"));

    final JSONControlDecodeHelper control =
         new JSONControlDecodeHelper(controlObject, false, true, false);

    assertEquals(control.getOID(), "1.2.3.4");

    assertFalse(control.getCriticality());

    assertNull(control.getRawValue());

    assertNull(control.getValueObject());

    assertNotNull(control.toString());
  }
}
