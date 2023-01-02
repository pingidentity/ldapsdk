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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of unit tests for the
 * IntermediateClientRequestControl class.
 */
public class IntermediateClientRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with all non-{@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NonNull()
         throws Exception
  {
    IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(null, "1.2.3.4", true, "u:end-user",
                                            "directory-enabled app",
                                            "webapp-session-id",
                                            "webapp-request-id");

    IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(downstreamRequest, "1.2.3.5",
                  true, "u:webapp", "directory proxy", "conn=123", "op=456");

    c = new IntermediateClientRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getRequestValue());

    assertNotNull(c.getDownstreamRequest());
    assertEquals(c.getDownstreamRequest(), downstreamRequest);

    assertNotNull(c.getDownstreamClientAddress());
    assertEquals(c.getDownstreamClientAddress(), "1.2.3.5");

    assertNotNull(c.downstreamClientSecure());
    assertEquals(c.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(c.getClientIdentity());
    assertEquals(c.getClientIdentity(), "u:webapp");

    assertNotNull(c.getClientName());
    assertEquals(c.getClientName(), "directory proxy");

    assertNotNull(c.getClientSessionID());
    assertEquals(c.getClientSessionID(), "conn=123");

    assertNotNull(c.getClientRequestID());
    assertEquals(c.getClientRequestID(), "op=456");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with all {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Null()
         throws Exception
  {
    IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(null, null, null, null, null,
                                              null, null);

    c = new IntermediateClientRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getRequestValue());

    assertNull(c.getDownstreamRequest());

    assertNull(c.getDownstreamClientAddress());

    assertNull(c.downstreamClientSecure());

    assertNull(c.getClientIdentity());

    assertNull(c.getClientName());

    assertNull(c.getClientSessionID());

    assertNull(c.getClientRequestID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a request value containing all
   * non-{@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonNullElements()
         throws Exception
  {
    IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(null, "1.2.3.4", true, "u:end-user",
                                            "directory-enabled app",
                                            "webapp-session-id",
                                            "webapp-request-id");

    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(downstreamRequest, "1.2.3.5",
                  true, "u:webapp", "directory proxy", "conn=123", "op=456");

    IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(v);

    c = new IntermediateClientRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getRequestValue());
    assertEquals(c.getRequestValue(), v);

    assertNotNull(c.getDownstreamRequest());
    assertEquals(c.getDownstreamRequest(), downstreamRequest);

    assertNotNull(c.getDownstreamClientAddress());
    assertEquals(c.getDownstreamClientAddress(), "1.2.3.5");

    assertNotNull(c.downstreamClientSecure());
    assertEquals(c.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(c.getClientIdentity());
    assertEquals(c.getClientIdentity(), "u:webapp");

    assertNotNull(c.getClientName());
    assertEquals(c.getClientName(), "directory proxy");

    assertNotNull(c.getClientSessionID());
    assertEquals(c.getClientSessionID(), "conn=123");

    assertNotNull(c.getClientRequestID());
    assertEquals(c.getClientRequestID(), "op=456");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a request value containing all
   * {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullElements()
         throws Exception
  {
    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(null, null, null, null, null, null,
                                            null);

    IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(v);
    c = new IntermediateClientRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getRequestValue());
    assertEquals(c.getRequestValue(), v);

    assertNull(c.getDownstreamRequest());

    assertNull(c.getDownstreamClientAddress());

    assertNull(c.downstreamClientSecure());

    assertNull(c.getClientIdentity());

    assertNull(c.getClientName());

    assertNull(c.getClientSessionID());

    assertNull(c.getClientRequestID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a request value containing all
   * {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullElements()
         throws Exception
  {
    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(null, null, null, null, null, null,
                                            null);

    IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(false, v);
    c = new IntermediateClientRequestControl(c);

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getRequestValue());
    assertEquals(c.getRequestValue(), v);

    assertNull(c.getDownstreamRequest());

    assertNull(c.getDownstreamClientAddress());

    assertNull(c.downstreamClientSecure());

    assertNull(c.getClientIdentity());

    assertNull(c.getClientName());

    assertNull(c.getClientSessionID());

    assertNull(c.getClientRequestID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a control that doesn't have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions  = { LDAPException.class })
  public void testConstructor4NoValue()
         throws Exception
  {
    new IntermediateClientRequestControl(
             new Control("1.3.6.1.4.1.30221.2.5.2"));
  }



  /**
   * Tests the fourth constructor with a control that has an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions  = { LDAPException.class })
  public void testConstructor4InvalidValue()
         throws Exception
  {
    new IntermediateClientRequestControl(
             new Control("1.3.6.1.4.1.30221.2.5.2", true,
                         new ASN1OctetString(new byte[1])));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control does not have any elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoElements()
          throws Exception
  {
    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(false,
              new IntermediateClientRequestValue(null, null, null, null, null,
                   null, null));

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
         JSONObject.EMPTY_OBJECT);


    IntermediateClientRequestControl decodedControl =
         IntermediateClientRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getDownstreamRequest());

    assertNull(decodedControl.getDownstreamClientAddress());

    assertNull(decodedControl.downstreamClientSecure());

    assertNull(decodedControl.getClientIdentity());

    assertNull(decodedControl.getClientName());

    assertNull(decodedControl.getClientSessionID());

    assertNull(decodedControl.getClientRequestID());


    decodedControl =
         (IntermediateClientRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNull(decodedControl.getDownstreamRequest());

    assertNull(decodedControl.getDownstreamClientAddress());

    assertNull(decodedControl.downstreamClientSecure());

    assertNull(decodedControl.getClientIdentity());

    assertNull(decodedControl.getClientName());

    assertNull(decodedControl.getClientSessionID());

    assertNull(decodedControl.getClientRequestID());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control includes all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElements()
          throws Exception
  {
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

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
              new JSONField("downstream-request", new JSONObject(
                   new JSONField("downstream-request", new JSONObject(
                        new JSONField("downstream-client-address",
                             "further-downstream-address"),
                        new JSONField("downstream-client-secure", false),
                        new JSONField("client-identity",
                             "further-downstream-client-identity"),
                        new JSONField("client-name",
                             "further-downstream-client-name"),
                        new JSONField("client-session-id",
                             "further-downstream-client-session-id"),
                        new JSONField("client-request-id",
                             "further-downstream-client-request-id"))),
                   new JSONField("downstream-client-address",
                        "downstream-address"),
                   new JSONField("downstream-client-secure", true),
                   new JSONField("client-identity",
                        "downstream-client-identity"),
                   new JSONField("client-name",
                        "downstream-client-name"),
                   new JSONField("client-session-id",
                        "downstream-client-session-id"),
                   new JSONField("client-request-id",
                        "downstream-client-request-id"))),
              new JSONField("downstream-client-address", "address"),
              new JSONField("downstream-client-secure", false),
              new JSONField("client-identity", "client-identity"),
              new JSONField("client-name", "client-name"),
              new JSONField("client-session-id", "client-session-id"),
              new JSONField("client-request-id", "client-request-id")));


    IntermediateClientRequestControl decodedControl =
         IntermediateClientRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");


    decodedControl =
         (IntermediateClientRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");
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
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    IntermediateClientRequestControl decodedControl =
         IntermediateClientRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");


    decodedControl =
         (IntermediateClientRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnexpectedFieldStrict()
          throws Exception
  {
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("downstream-request", new JSONObject(
                   new JSONField("downstream-request", new JSONObject(
                        new JSONField("downstream-client-address",
                             "further-downstream-address"),
                        new JSONField("downstream-client-secure", false),
                        new JSONField("client-identity",
                             "further-downstream-client-identity"),
                        new JSONField("client-name",
                             "further-downstream-client-name"),
                        new JSONField("client-session-id",
                             "further-downstream-client-session-id"),
                        new JSONField("client-request-id",
                             "further-downstream-client-request-id"))),
                   new JSONField("downstream-client-address",
                        "downstream-address"),
                   new JSONField("downstream-client-secure", true),
                   new JSONField("client-identity",
                        "downstream-client-identity"),
                   new JSONField("client-name",
                        "downstream-client-name"),
                   new JSONField("client-session-id",
                        "downstream-client-session-id"),
                   new JSONField("client-request-id",
                        "downstream-client-request-id"))),
              new JSONField("downstream-client-address", "address"),
              new JSONField("downstream-client-secure", false),
              new JSONField("client-identity", "client-identity"),
              new JSONField("client-name", "client-name"),
              new JSONField("client-session-id", "client-session-id"),
              new JSONField("client-request-id", "client-request-id"),
              new JSONField("unrecognized", "foo"))));


    IntermediateClientRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnexpectedFieldNonStrict()
          throws Exception
  {
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("downstream-request", new JSONObject(
                   new JSONField("downstream-request", new JSONObject(
                        new JSONField("downstream-client-address",
                             "further-downstream-address"),
                        new JSONField("downstream-client-secure", false),
                        new JSONField("client-identity",
                             "further-downstream-client-identity"),
                        new JSONField("client-name",
                             "further-downstream-client-name"),
                        new JSONField("client-session-id",
                             "further-downstream-client-session-id"),
                        new JSONField("client-request-id",
                             "further-downstream-client-request-id"))),
                   new JSONField("downstream-client-address",
                        "downstream-address"),
                   new JSONField("downstream-client-secure", true),
                   new JSONField("client-identity",
                        "downstream-client-identity"),
                   new JSONField("client-name",
                        "downstream-client-name"),
                   new JSONField("client-session-id",
                        "downstream-client-session-id"),
                   new JSONField("client-request-id",
                        "downstream-client-request-id"))),
              new JSONField("downstream-client-address", "address"),
              new JSONField("downstream-client-secure", false),
              new JSONField("client-identity", "client-identity"),
              new JSONField("client-name", "client-name"),
              new JSONField("client-session-id", "client-session-id"),
              new JSONField("client-request-id", "client-request-id"),
              new JSONField("unrecognized", "foo"))));


    IntermediateClientRequestControl decodedControl =
         IntermediateClientRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");


    decodedControl =
         (IntermediateClientRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * a downstream value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlDownstreamValueUnexpectedFieldStrict()
          throws Exception
  {
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("downstream-request", new JSONObject(
                   new JSONField("downstream-request", new JSONObject(
                        new JSONField("downstream-client-address",
                             "further-downstream-address"),
                        new JSONField("downstream-client-secure", false),
                        new JSONField("client-identity",
                             "further-downstream-client-identity"),
                        new JSONField("client-name",
                             "further-downstream-client-name"),
                        new JSONField("client-session-id",
                             "further-downstream-client-session-id"),
                        new JSONField("client-request-id",
                             "further-downstream-client-request-id"),
                        new JSONField("unrecognized", "foo"))),
                   new JSONField("downstream-client-address",
                        "downstream-address"),
                   new JSONField("downstream-client-secure", true),
                   new JSONField("client-identity",
                        "downstream-client-identity"),
                   new JSONField("client-name",
                        "downstream-client-name"),
                   new JSONField("client-session-id",
                        "downstream-client-session-id"),
                   new JSONField("client-request-id",
                        "downstream-client-request-id"))),
              new JSONField("downstream-client-address", "address"),
              new JSONField("downstream-client-secure", false),
              new JSONField("client-identity", "client-identity"),
              new JSONField("client-name", "client-name"),
              new JSONField("client-session-id", "client-session-id"),
              new JSONField("client-request-id", "client-request-id"))));


    IntermediateClientRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * a downstream value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlDownstreamValueUnexpectedFieldNonStrict()
          throws Exception
  {
    final IntermediateClientRequestValue furtherDownstreamRequest =
         new IntermediateClientRequestValue(null, "further-downstream-address",
              false, "further-downstream-client-identity",
              "further-downstream-client-name",
              "further-downstream-client-session-id",
              "further-downstream-client-request-id");

    final IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(furtherDownstreamRequest,
              "downstream-address", true, "downstream-client-identity",
              "downstream-client-name", "downstream-client-session-id",
              "downstream-client-request-id");

    final IntermediateClientRequestValue value =
         new IntermediateClientRequestValue(downstreamRequest, "address",
              false, "client-identity", "client-name", "client-session-id",
              "client-request-id");

    final IntermediateClientRequestControl c =
         new IntermediateClientRequestControl(true, value);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("downstream-request", new JSONObject(
                   new JSONField("downstream-request", new JSONObject(
                        new JSONField("downstream-client-address",
                             "further-downstream-address"),
                        new JSONField("downstream-client-secure", false),
                        new JSONField("client-identity",
                             "further-downstream-client-identity"),
                        new JSONField("client-name",
                             "further-downstream-client-name"),
                        new JSONField("client-session-id",
                             "further-downstream-client-session-id"),
                        new JSONField("client-request-id",
                             "further-downstream-client-request-id"),
                        new JSONField("unrecognized", "foo"))),
                   new JSONField("downstream-client-address",
                        "downstream-address"),
                   new JSONField("downstream-client-secure", true),
                   new JSONField("client-identity",
                        "downstream-client-identity"),
                   new JSONField("client-name",
                        "downstream-client-name"),
                   new JSONField("client-session-id",
                        "downstream-client-session-id"),
                   new JSONField("client-request-id",
                        "downstream-client-request-id"))),
              new JSONField("downstream-client-address", "address"),
              new JSONField("downstream-client-secure", false),
              new JSONField("client-identity", "client-identity"),
              new JSONField("client-name", "client-name"),
              new JSONField("client-session-id", "client-session-id"),
              new JSONField("client-request-id", "client-request-id"),
              new JSONField("unrecognized", "foo"))));


    IntermediateClientRequestControl decodedControl =
         IntermediateClientRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");


    decodedControl =
         (IntermediateClientRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getDownstreamRequest(), downstreamRequest);
    assertEquals(decodedControl.getDownstreamRequest().getClientName(),
         "downstream-client-name");
    assertEquals(
         decodedControl.getDownstreamRequest().getDownstreamRequest().
              getClientName(),
         "further-downstream-client-name");

    assertEquals(decodedControl.getDownstreamClientAddress(), "address");

    assertEquals(decodedControl.downstreamClientSecure(),
         Boolean.FALSE);

    assertEquals(decodedControl.getClientIdentity(), "client-identity");

    assertEquals(decodedControl.getClientName(), "client-name");

    assertEquals(decodedControl.getClientSessionID(), "client-session-id");

    assertEquals(decodedControl.getClientRequestID(), "client-request-id");
  }
}
