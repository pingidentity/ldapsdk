/*
 * Copyright 2008-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2023 Ping Identity Corporation
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
 * Copyright (C) 2008-2023 Ping Identity Corporation
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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides test coverage for the get authorization entry request
 * control.
 */
public class GetAuthorizationEntryRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl();
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, false);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, (String[]) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, "cn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, "givenName", "sn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, false,
                                                 Arrays.<String>asList());
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true,
                                                 (List<String>) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true,
                                                 Arrays.asList("cn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true,
                  Arrays.asList("givenName", "sn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, false);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, false, true,
                                                 (String[]) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, true, "cn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, true, "givenName",
                                                 "sn");
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor without any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NoAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, false,
                                                 Arrays.<String>asList());
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertFalse(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a null set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, false, true,
                                                 (List<String>) null);
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertFalse(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertTrue(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5SingleAttribute()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, true,
                                                 Arrays.asList("cn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5MultipleAttributes()
         throws Exception
  {
    GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, true,
                  Arrays.asList("givenName", "sn"));
    c = new GetAuthorizationEntryRequestControl(c);

    assertNotNull(c);

    assertTrue(c.includeAuthNEntry());

    assertTrue(c.includeAuthZEntry());

    assertNotNull(c.getAttributes());
    assertFalse(c.getAttributes().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor with a control value that is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueNotSequence()
         throws Exception
  {
    Control c = new Control("1.2.3.4", false,
                            new ASN1OctetString(new byte[1]));
    new GetAuthorizationEntryRequestControl(c);
  }



  /**
   * Tests the sixth constructor with a control value sequence containing an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueSequenceHasInvalidType()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence(new ASN1OctetString((byte) 0x00));
    Control c = new Control("1.2.3.4", false, new ASN1OctetString(s.encode()));
    new GetAuthorizationEntryRequestControl(c);
  }



  /**
   * Sends a request to the server containing the get authorization entry
   * request control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithGetAuthorizationEntryRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedConnection();

    try
    {
      BindResult bindResult = conn.bind(new SimpleBindRequest(getTestBindDN(),
           getTestBindPassword(),
           new GetAuthorizationEntryRequestControl(true, true, "*", "+")));

      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

      GetAuthorizationEntryResponseControl c =
           GetAuthorizationEntryResponseControl.get(bindResult);
      assertNotNull(c);

      assertTrue(c.isAuthenticated());

      assertTrue(c.identitiesMatch());

      assertNotNull(c.getAuthNID());
      assertNotNull(c.getAuthNEntry());

      assertNotNull(c.getAuthZID());
      assertNotNull(c.getAuthZEntry());

      assertNotNull(c.getControlName());

      assertNotNull(c.toString());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control does not list any specific attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutAttributes()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

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

    assertEquals(valueObject.getFieldAsBoolean("include-authentication-entry"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsBoolean("include-authorization-entry"),
         Boolean.FALSE);

    assertNull(valueObject.getFieldAsArray("attributes"));


    GetAuthorizationEntryRequestControl decodedControl =
         GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);


    decodedControl =
         (GetAuthorizationEntryRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control includes a list of requested
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributes()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(true, true, true,
              "uid", "givenName", "sn", "cn", "mail");

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

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 3);

    assertEquals(valueObject.getFieldAsBoolean("include-authentication-entry"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsBoolean("include-authorization-entry"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsArray("attributes"),
         Arrays.asList(new JSONString("uid"), new JSONString("givenName"),
              new JSONString("sn"), new JSONString("cn"),
              new JSONString("mail")));


    GetAuthorizationEntryRequestControl decodedControl =
         GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertTrue(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes(),
         Arrays.asList("uid", "givenName", "sn", "cn", "mail"));


    decodedControl =
         (GetAuthorizationEntryRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertTrue(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes(),
         Arrays.asList("uid", "givenName", "sn", "cn", "mail"));
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetAuthorizationEntryRequestControl decodedControl =
         GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);


    decodedControl =
         (GetAuthorizationEntryRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value object is missing the include-authentication-entry field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingIncludeAuthenticationEntry()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-authorization-entry", false),
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"))))));

    GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value object is missing the include-authorization-entry field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingIncludeAuthorizationEntry()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-authentication-entry", true),
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"))))));

    GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value object has a non-string value in the attributes array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNonStringAttribute()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-authentication-entry", true),
              new JSONField("include-authorization-entry", false),
              new JSONField("attributes", new JSONArray(
                   new JSONNumber(1234))))));

    GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-authentication-entry", true),
              new JSONField("include-authorization-entry", false),
              new JSONField("unrecognized", "foo"))));

    GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object to a control when
   * the value object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final GetAuthorizationEntryRequestControl c =
         new GetAuthorizationEntryRequestControl(false, true, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-authentication-entry", true),
              new JSONField("include-authorization-entry", false),
              new JSONField("unrecognized", "foo"))));


    GetAuthorizationEntryRequestControl decodedControl =
         GetAuthorizationEntryRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);


    decodedControl =
         (GetAuthorizationEntryRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertTrue(decodedControl.includeAuthNEntry());

    assertFalse(decodedControl.includeAuthZEntry());

    assertEquals(decodedControl.getAttributes().size(), 0);
  }
}
