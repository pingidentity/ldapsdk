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
import com.unboundid.asn1.ASN1Integer;
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
 * This class provides a set of test cases for the
 * VirtualListViewResponseControl class.
 */
public class VirtualListViewResponseControlTestCase
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
   * Tests the second constructor with a non-{@code null} context ID.
   */
  @Test()
  public void testConstructor2()
  {
    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl(1, 10, ResultCode.SUCCESS,
                                            new ASN1OctetString());

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertEquals(c.getTargetPosition(), 1);
    assertEquals(c.getContentCount(), 10);
    assertNotNull(c.getContextID());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} context ID.
   */
  @Test()
  public void testConstructor2NullContextID()
  {
    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl(1, 10, ResultCode.SUCCESS, null);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);
    assertEquals(c.getTargetPosition(), 1);
    assertEquals(c.getContentCount(), 10);
    assertNull(c.getContextID());
    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor including a context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithContextID()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1Integer(100),
      new ASN1Enumerated(0),
      new ASN1OctetString(new byte[1])
    };

    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
                  new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getTargetPosition(), 10);

    assertEquals(c.getContentCount(), 100);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor not including a context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithoutContextID()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1Integer(100),
      new ASN1Enumerated(0)
    };

    VirtualListViewResponseControl c =
         new VirtualListViewResponseControl().decodeControl(
              "2.16.840.1.113730.3.4.10", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getTargetPosition(), 10);

    assertEquals(c.getContentCount(), 100);

    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getContextID());

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
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false, null);
  }



  /**
   * Tests the third constructor with a value that can't be decoded as a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1OctetString(new byte[1]).encode()));
  }



  /**
   * Tests the third constructor with a value sequence with an invalid number of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidLength()
         throws Exception
  {
    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the first
   * element cannot be decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceFirstElementNotInteger()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString(),
      new ASN1Integer(10),
      new ASN1Enumerated(0)
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the second
   * element cannot be decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotInteger()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(5),
      new ASN1OctetString(),
      new ASN1Enumerated(0)
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the third constructor with a value sequence in which the third
   * element cannot be decoded as an enumerated element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceSecondElementNotEnumerated()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(5),
      new ASN1Integer(10),
      new ASN1OctetString()
    };

    new VirtualListViewResponseControl("2.16.840.1.113730.3.4.10", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a virtual
   * list view response control.
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

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
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
      new VirtualListViewResponseControl(1, 123, ResultCode.SUCCESS,
           new ASN1OctetString("foo"))
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getTargetPosition(), 1);

    assertEquals(c.getContentCount(), 123);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());
    assertEquals(c.getContextID().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a virtual list view
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new VirtualListViewResponseControl(1, 123,
         ResultCode.SUCCESS, new ASN1OctetString("foo"));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final VirtualListViewResponseControl c =
         VirtualListViewResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getTargetPosition(), 1);

    assertEquals(c.getContentCount(), 123);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(c.getContextID());
    assertEquals(c.getContextID().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a virtual list view
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
      new Control(VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID,
           false, null)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    VirtualListViewResponseControl.get(r);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is no context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutContextID()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         0, 0, ResultCode.SORT_CONTROL_MISSING, null);


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
              new JSONField("result-code", 60),
              new JSONField("target-position", 0),
              new JSONField("content-count", 0)));


    VirtualListViewResponseControl decodedControl =
         VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.SORT_CONTROL_MISSING);

    assertEquals(decodedControl.getTargetPosition(), 0);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());


    decodedControl =
         (VirtualListViewResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(),
         ResultCode.SORT_CONTROL_MISSING);

    assertEquals(decodedControl.getTargetPosition(), 0);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there is a context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithContextID()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


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
              new JSONField("result-code", 0),
              new JSONField("target-position", 1),
              new JSONField("content-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID"))));


    VirtualListViewResponseControl decodedControl =
         VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");


    decodedControl =
         (VirtualListViewResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value is
   * base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    VirtualListViewResponseControl decodedControl =
         VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");


    decodedControl =
         (VirtualListViewResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value is
   * missing the result-code field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingResultCode()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-position", 1),
              new JSONField("content-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value is
   * missing the target-position field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingTargetPosition()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("content-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value is
   * missing the content-count field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingContentCount()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("target-position", 1),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value has
   * a context-id value that is not valid base4.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueContextIDNotBase64()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("target-position", 1),
              new JSONField("content-count", 12345),
              new JSONField("context-id", "not valid base64"))));

    VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value has
   * an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("target-position", 1),
              new JSONField("content-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")),
              new JSONField("unrecognized", "foo"))));

    VirtualListViewResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object when the value has
   * an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final VirtualListViewResponseControl c = new VirtualListViewResponseControl(
         1, 12345, ResultCode.SUCCESS, new ASN1OctetString("TheContextID"));


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("target-position", 1),
              new JSONField("content-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")),
              new JSONField("unrecognized", "foo"))));


    VirtualListViewResponseControl decodedControl =
         VirtualListViewResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");


    decodedControl =
         (VirtualListViewResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getTargetPosition(), 1);

    assertEquals(decodedControl.getContentCount(), 12345);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");
  }
}
