/*
 * Copyright 2007-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2025 Ping Identity Corporation
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
 * Copyright (C) 2007-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the ServerSideSortResponseControl
 * class.
 */
public class ServerSideSortResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new ServerSideSortResponseControl();
  }



  /**
   * Tests the second constructor with an attribute name.
   */
  @Test()
  public void testConstructor2WithAttribute()
  {
    ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.SUCCESS, "cn");
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertEquals(c.getAttributeName(), "cn");
    assertFalse(c.isCritical());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor without an attribute name.
   */
  @Test()
  public void testConstructor2WithoutAttribute()
  {
    ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.SUCCESS, null);
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertNull(c.getAttributeName());
    assertFalse(c.isCritical());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a control that has an attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithAttribute()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(80),
      new ASN1OctetString("cn")
    };

    ServerSideSortResponseControl c =
         new ServerSideSortResponseControl("1.2.840.113556.1.4.474", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getResultCode(), ResultCode.OTHER);

    assertNotNull(c.getAttributeName());
    assertEquals(c.getAttributeName(), "cn");

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a control that does not have an attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithoutAttribute()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(0)
    };

    ServerSideSortResponseControl c =
         new ServerSideSortResponseControl().decodeControl(
              "1.2.840.113556.1.4.474", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getAttributeName());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NullValue()
         throws Exception
  {
    new ServerSideSortResponseControl("1.2.840.113556.1.4.474", false, null);
  }



  /**
   * Tests the third constructor with a {@code null} value that is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    new ServerSideSortResponseControl("1.2.840.113556.1.4.474", false,
             new ASN1OctetString(new byte[1]));
  }



  /**
   * Tests the third constructor with a {@code null} value that has an invalid
   * number of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidCount()
         throws Exception
  {
    new ServerSideSortResponseControl("1.2.840.113556.1.4.474", false,
             new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the third constructor with a {@code null} value sequence in which the
   * first element cannot be decoded as an enumerated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceFirstNotEnumerated()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString()
    };

    new ServerSideSortResponseControl("1.2.840.113556.1.4.474", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a
   * server-side sort response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final ServerSideSortResponseControl c =
         ServerSideSortResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new ServerSideSortResponseControl(ResultCode.SUCCESS, null)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final ServerSideSortResponseControl c =
         ServerSideSortResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getAttributeName());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a server-side sort response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new ServerSideSortResponseControl(ResultCode.SUCCESS,
         null);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final ServerSideSortResponseControl c =
         ServerSideSortResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getAttributeName());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a server-side sort
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID,
           false, null)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    ServerSideSortResponseControl.get(r);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is no attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutAttributeName()
          throws Exception
  {
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.SUCCESS, null);

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
              new JSONField("result-code", 0)));


    ServerSideSortResponseControl decodedControl =
         ServerSideSortResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertNull(decodedControl.getAttributeName());


    decodedControl =
         (ServerSideSortResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertNull(decodedControl.getAttributeName());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is an attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributeName()
          throws Exception
  {
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              "undefinedAttr");

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
              new JSONField("result-code", 17),
              new JSONField("attribute-name", "undefinedAttr")));


    ServerSideSortResponseControl decodedControl =
         ServerSideSortResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");


    decodedControl =
         (ServerSideSortResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");
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
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              "undefinedAttr");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    ServerSideSortResponseControl decodedControl =
         ServerSideSortResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");


    decodedControl =
         (ServerSideSortResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the result-code field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingResultCode()
          throws Exception
  {
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              "undefinedAttr");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-name", "undefinedAttr"))));

    ServerSideSortResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value includes an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              "undefinedAttr");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 17),
              new JSONField("attribute-name", "undefinedAttr"),
              new JSONField("unrecognized", "foo"))));

    ServerSideSortResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value includes an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final ServerSideSortResponseControl c =
         new ServerSideSortResponseControl(ResultCode.UNDEFINED_ATTRIBUTE_TYPE,
              "undefinedAttr");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 17),
              new JSONField("attribute-name", "undefinedAttr"),
              new JSONField("unrecognized", "foo"))));


    ServerSideSortResponseControl decodedControl =
         ServerSideSortResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");


    decodedControl =
         (ServerSideSortResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.UNDEFINED_ATTRIBUTE_TYPE);

    assertEquals(decodedControl.getAttributeName(), "undefinedAttr");
  }
}
