/*
 * Copyright 2010-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2022 Ping Identity Corporation
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
 * Copyright (C) 2010-2022 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * {@code RouteToServerRequestControl} class.
 */
public class RouteToServerRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the control with a number of configurations.
   *
   * @param  isCritical                 Indicates whether the server should be
   *                                    critical.
   * @param  allowAlternate             The allow alternate value to use when
   *                                    creating the control.
   * @param  preferLocal                The prefer local value to use when
   *                                    creating the control.
   * @param  preferNonDegraded          The prefer non-degraded value to use
   *                                    when creating the control.
   * @param  expectedAllowAlternate     The allow alternate server value for the
   *                                    resulting control.
   * @param  expectedPreferLocal        The expected prefer local value for the
   *                                    resulting control.
   * @param  expectedPreferNonDegraded  The expected prefer non-degraded value
   *                                    for the resulting control.
   *
   * Tests the control with a configuration that will always allow alternate
   * servers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testConfigs")
  public void testAlwaysAllowAlternate(final boolean isCritical,
                                       final boolean allowAlternate,
                                       final boolean preferLocal,
                                       final boolean preferNonDegraded,
                                       final boolean expectedAllowAlternate,
                                       final boolean expectedPreferLocal,
                                       final boolean expectedPreferNonDegraded)
         throws Exception
  {
    final String serverID = CryptoHelper.getRandomUUID().toString();

    RouteToServerRequestControl c = new RouteToServerRequestControl(isCritical,
         serverID, allowAlternate, preferLocal, preferNonDegraded);
    c = new RouteToServerRequestControl(c);

    assertEquals(c.isCritical(), isCritical);

    assertNotNull(c.getServerID());
    assertEquals(c.getServerID(), serverID);

    assertEquals(c.allowAlternateServer(), expectedAllowAlternate);

    assertEquals(c.preferLocalServer(), expectedPreferLocal);

    assertEquals(c.preferNonDegradedServer(), expectedPreferNonDegraded);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Retrieves a set of configurations that may be used to test the control.
   *
   * @return  A set of configurations that may be used to test the control.
   */
  @DataProvider(name="testConfigs")
  public Object[][] getTestConfigs()
  {
    return new Object[][]
    {
      new Object[] { true, true, true, true, true, true, true },
      new Object[] { true, false, false, false, false, false, false },
      new Object[] { true, false, true, true, false, false, false },
      new Object[] { true, true, false, true, true, false, true },
      new Object[] { true, true, true, false, true, true, false },
      new Object[] { false, true, true, true, true, true, true },
      new Object[] { false, false, false, false, false, false, false },
      new Object[] { false, false, true, true, false, false, false },
      new Object[] { false, true, false, true, true, false, true },
      new Object[] { false, true, true, false, true, true, false },
    };
  }



  /**
   * Tests the ability to decode a control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true, null));
  }



  /**
   * Tests the ability to decode a control whose value is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString("foo")));
  }



  /**
   * Tests the ability to decode a control with an empty value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueEmptySequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence();

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the ability to decode a control with a malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "foo"),
         new ASN1OctetString((byte) 0x81, "bar"));

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the ability to decode a control with a value sequence containing an
   * unexpected element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "foo"),
         new ASN1Boolean((byte) 0x82, true),
         new ASN1Boolean((byte) 0x00, true));

    new RouteToServerRequestControl(new Control(
         RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID, true,
         new ASN1OctetString(valueSequence.encode())));
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
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, true);

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
              new JSONField("server-id", "serverID"),
              new JSONField("allow-alternate-server", true),
              new JSONField("prefer-local-server", false),
              new JSONField("prefer-non-degraded-server", true)));


    RouteToServerRequestControl decodedControl =
         RouteToServerRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertTrue(decodedControl.preferNonDegradedServer());


    decodedControl =
         (RouteToServerRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertTrue(decodedControl.preferNonDegradedServer());
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
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    RouteToServerRequestControl decodedControl =
         RouteToServerRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());


    decodedControl =
         (RouteToServerRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the server-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingServerID()
          throws Exception
  {
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("allow-alternate-server", true),
              new JSONField("prefer-local-server", false),
              new JSONField("prefer-non-degraded-server", false))));

    RouteToServerRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the allow-alternate-server field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingAllowAlternateServer()
          throws Exception
  {
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "serverID"),
              new JSONField("prefer-local-server", false),
              new JSONField("prefer-non-degraded-server", false))));

    RouteToServerRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the prefer-local-server field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueMissingPreferLocalServer()
          throws Exception
  {
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "serverID"),
              new JSONField("allow-alternate-server", true),
              new JSONField("prefer-non-degraded-server", false))));


    RouteToServerRequestControl decodedControl =
         RouteToServerRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertTrue(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());


    decodedControl =
         (RouteToServerRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertTrue(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the prefer-non-degraded-server field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueMissingPreferNonDegradedServer()
          throws Exception
  {
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", true, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "serverID"),
              new JSONField("allow-alternate-server", true),
              new JSONField("prefer-local-server", false))));


    RouteToServerRequestControl decodedControl =
         RouteToServerRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertTrue(decodedControl.preferNonDegradedServer());


    decodedControl =
         (RouteToServerRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertTrue(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertTrue(decodedControl.preferNonDegradedServer());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", false, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "serverID"),
              new JSONField("allow-alternate-server", false),
              new JSONField("prefer-local-server", false),
              new JSONField("prefer-non-degraded-server", false),
              new JSONField("unrecognized", "foo"))));


    RouteToServerRequestControl.decodeJSONControl(controlObject, true);
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
    final RouteToServerRequestControl c = new RouteToServerRequestControl(false,
         "serverID", false, false, false);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "serverID"),
              new JSONField("allow-alternate-server", false),
              new JSONField("prefer-local-server", false),
              new JSONField("prefer-non-degraded-server", false),
              new JSONField("unrecognized", "foo"))));


    RouteToServerRequestControl decodedControl =
         RouteToServerRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertFalse(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());


    decodedControl =
         (RouteToServerRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "serverID");

    assertFalse(decodedControl.allowAlternateServer());

    assertFalse(decodedControl.preferLocalServer());

    assertFalse(decodedControl.preferNonDegradedServer());
  }
}
