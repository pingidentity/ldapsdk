/*
 * Copyright 2012-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2025 Ping Identity Corporation
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
 * Copyright (C) 2012-2025 Ping Identity Corporation
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



import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the suppress operational
 * attribute update request control.
 */
public final class SuppressOperationalAttributeUpdateRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control created with the constructor that uses
   * only a varargs set of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsWithoutCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(
              SuppressType.LAST_ACCESS_TIME);

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LAST_ACCESS_TIME));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses a
   * criticality and a varargs set of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsWithCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              SuppressType.LAST_ACCESS_TIME, SuppressType.LAST_LOGIN_TIME,
              SuppressType.LAST_LOGIN_IP, SuppressType.LASTMOD);

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(), EnumSet.allOf(SuppressType.class));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses
   * only a collection of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionWithoutCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(
              EnumSet.of(SuppressType.LASTMOD));

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LASTMOD));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses a
   * criticality and a collection of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionWithCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              EnumSet.of(SuppressType.LAST_LOGIN_TIME,
                   SuppressType.LAST_LOGIN_IP));

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LAST_LOGIN_TIME,
              SuppressType.LAST_LOGIN_IP));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic control that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27"));
  }



  /**
   * Tests the behavior when trying to decode a generic control that cannot be
   * decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27", false,
              new ASN1OctetString("this is a malformed value")));
  }



  /**
   * Tests the behavior when trying to decode a generic control that cannot be
   * decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueUnrecognizedSuppressType()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27", false,
              new ASN1OctetString(
                   new ASN1Sequence(
                        new ASN1Sequence((byte) 0x80,
                             new ASN1Enumerated(1234))).encode())));
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
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

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
              new JSONField("suppress-types", new JSONArray(
                   new JSONString("last-access-time"),
                   new JSONString("last-login-time"),
                   new JSONString("last-login-ip-address"),
                   new JSONString("lastmod")))));


    SuppressOperationalAttributeUpdateRequestControl decodedControl =
         SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
              controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);


    decodedControl =
         (SuppressOperationalAttributeUpdateRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);
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
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    SuppressOperationalAttributeUpdateRequestControl decodedControl =
         SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
              controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);


    decodedControl =
         (SuppressOperationalAttributeUpdateRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the suppress-types field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingSuppressTypes()
          throws Exception
  {
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
         controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an empty suppress-types array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueEmptySuppressTypes()
          throws Exception
  {
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("suppress-types", JSONArray.EMPTY_ARRAY))));

    SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
         controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an unrecognized suppress-types value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedSuppressType()
          throws Exception
  {
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("suppress-types", new JSONArray(
                   new JSONString("last-access-time"),
                   new JSONString("last-login-time"),
                   new JSONString("last-login-ip-address"),
                   new JSONString("lastmod"),
                   new JSONString("unrecognized"))))));

    SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
         controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has a suppress-types value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNonStringSuppressType()
          throws Exception
  {
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("suppress-types", new JSONArray(
                   new JSONString("last-access-time"),
                   new JSONString("last-login-time"),
                   new JSONString("last-login-ip-address"),
                   new JSONString("lastmod"),
                   new JSONNumber(1234))))));

    SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
         controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedStrict()
          throws Exception
  {
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("suppress-types", new JSONArray(
                   new JSONString("last-access-time"),
                   new JSONString("last-login-time"),
                   new JSONString("last-login-ip-address"),
                   new JSONString("lastmod"))),
              new JSONField("unrecognized", "foo"))));

    SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
         controlObject, true);
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
    final Set<SuppressType> suppressTypes = new LinkedHashSet<>();
    suppressTypes.add(SuppressType.LAST_ACCESS_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_TIME);
    suppressTypes.add(SuppressType.LAST_LOGIN_IP);
    suppressTypes.add(SuppressType.LASTMOD);

    final SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              suppressTypes);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("suppress-types", new JSONArray(
                   new JSONString("last-access-time"),
                   new JSONString("last-login-time"),
                   new JSONString("last-login-ip-address"),
                   new JSONString("lastmod"))),
              new JSONField("unrecognized", "foo"))));


    SuppressOperationalAttributeUpdateRequestControl decodedControl =
         SuppressOperationalAttributeUpdateRequestControl.decodeJSONControl(
              controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);


    decodedControl =
         (SuppressOperationalAttributeUpdateRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getSuppressTypes(), suppressTypes);
  }
}
