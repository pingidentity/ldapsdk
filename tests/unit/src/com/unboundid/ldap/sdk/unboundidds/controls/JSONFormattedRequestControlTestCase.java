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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the
 * {@code JSONFormattedRequestControl} class.
 */
public final class JSONFormattedRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a JSON-formatted request control with no embedded
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyControl()
         throws Exception
  {
    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createEmptyControl(true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));

    assertNotNull(c.toString());


    c = new JSONFormattedRequestControl(c);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));

    assertNotNull(c.toString());


    c = (JSONFormattedRequestControl)
         Control.decodeJSONControl(controlObject, true, true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a JSON-formatted request control created with a set
   * of embedded controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithEmbeddedControls()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertEquals(decodedControls.size(), 2);
    assertEquals(decodedControls.get(0).toJSONControl(), gazRC.toJSONControl());
    assertEquals(decodedControls.get(1).toJSONControl(), riRC.toJSONControl());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());


    c = new JSONFormattedRequestControl(c);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());


    c = (JSONFormattedRequestControl)
         Control.decodeJSONControl(controlObject, true, true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a JSON-formatted request control created with a set
   * of embedded JSON objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithEmbeddedJSONObjects()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              gazRC.toJSONControl(), riRC.toJSONControl());

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertEquals(decodedControls.size(), 2);
    assertEquals(decodedControls.get(0).toJSONControl(), gazRC.toJSONControl());
    assertEquals(decodedControls.get(1).toJSONControl(), riRC.toJSONControl());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());


    c = new JSONFormattedRequestControl(c);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());


    c = (JSONFormattedRequestControl)
         Control.decodeJSONControl(controlObject, true, true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", new JSONArray(
                        new JSONObject(
                             new JSONField("oid", gazRC.getOID()),
                             new JSONField("control-name",
                                  gazRC.getControlName()),
                             new JSONField("criticality", gazRC.isCritical()),
                             new JSONField("value-json", new JSONObject(
                                  new JSONField("include-authentication-entry",
                                       true),
                                  new JSONField("include-authorization-entry",
                                       true),
                                  new JSONField("attributes", new JSONArray(
                                       new JSONString("uid"),
                                       new JSONString("givenName"),
                                       new JSONString("sn"),
                                       new JSONString("cn"),
                                       new JSONString("mail")))))),
                        new JSONObject(
                             new JSONField("oid", riRC.getOID()),
                             new JSONField("control-name",
                                  riRC.getControlName()),
                             new JSONField("criticality",
                                  riRC.isCritical()))))))));

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for the {@code createWithControls} method for a
   * {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithControlsNull()
         throws Exception
  {
    final Control[] controls = null;

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, controls);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    final List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    final JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));
  }



  /**
   * Tests the behavior for the {@code createWithControls} method for an empty
   * set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithControlsEmpty()
         throws Exception
  {
    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    final List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    final JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));
  }



  /**
   * Tests the behavior for the {@code createWithControlObjects} method for a
   * {@code null} set of objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithControlObjectsNull()
         throws Exception
  {
    final JSONObject[] controlObjects = null;

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              controlObjects);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    final List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    final JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));
  }



  /**
   * Tests the behavior for the {@code createWithControlObjects} method for an
   * empty set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithControlObjectsEmpty()
         throws Exception
  {
    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    final List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    final JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true)));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value that
   * is not a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotJSONObject()
         throws Exception
  {
    new JSONFormattedRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.64", true,
         new ASN1OctetString("Not a JSON object")));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value that
   * is an empty JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueEmptyJSONObject()
         throws Exception
  {
    new JSONFormattedRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.64", true,
         new ASN1OctetString(JSONObject.EMPTY_OBJECT.toSingleLineString())));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value with
   * a controls array that is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlValueControlsArrayEmpty()
         throws Exception
  {
    final JSONObject valueObject = new JSONObject(
         new JSONField("controls", JSONArray.EMPTY_ARRAY));

    final JSONFormattedRequestControl c = new JSONFormattedRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.64", true,
              new ASN1OctetString(valueObject.toSingleLineString())));

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());

    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    decodeBehavior.setThrowOnUnparsableObject(true);
    decodeBehavior.setThrowOnInvalidCriticalControl(true);
    decodeBehavior.setThrowOnInvalidNonCriticalControl(true);
    decodeBehavior.setStrict(true);

    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    final List<Control> decodedControls =
         c.decodeEmbeddedControls(decodeBehavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());
    assertTrue(nonFatalDecodeMessages.isEmpty());

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");

    final JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);
    assertEquals(controlObject,
         new JSONObject(
              new JSONField("oid", "1.3.6.1.4.1.30221.2.5.64"),
              new JSONField("control-name", "JSON-Formatted Request Control"),
              new JSONField("criticality", true),
              new JSONField("value-json", new JSONObject(
                   new JSONField("controls", JSONArray.EMPTY_ARRAY)))));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value with
   * a controls element with a value that isn't a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueControlsItemNotObject()
         throws Exception
  {
    final JSONObject valueObject = new JSONObject(
         new JSONField("controls", new JSONArray(
              new JSONString("Not an object"))));

    new JSONFormattedRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.64", true,
         new ASN1OctetString(valueObject.toSingleLineString())));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value with
   * a controls element with a value that is an object that can['t be parsed as
   * a valid control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueControlsObjectNotValidControl()
         throws Exception
  {
    final JSONObject valueObject = new JSONObject(
         new JSONField("controls", new JSONArray(
              new JSONObject(
                   new JSONField("foo", "bar")))));

    new JSONFormattedRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.64", true,
         new ASN1OctetString(valueObject.toSingleLineString())));
  }



  /**
   * Tests the behavior when trying to decode a control that has a value with
   * a controls element with a value that contains an unrecognized field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueUnrecognizedField()
         throws Exception
  {
    final JSONObject valueObject = new JSONObject(
         new JSONField("controls", JSONArray.EMPTY_ARRAY),
         new JSONField("unrecognized", "foo"));

    new JSONFormattedRequestControl(new Control(
         "1.3.6.1.4.1.30221.2.5.64", true,
         new ASN1OctetString(valueObject.toSingleLineString())));
  }



  /**
   * Tests the behavior when trying to use the {@code decodeEmbeddedControls}
   * method with an object that is not a valid generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEmbeddedControlsNotValidGenericControl()
         throws Exception
  {
    final JSONObject embeddedControlObject = JSONObject.EMPTY_OBJECT;

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              embeddedControlObject);


    // First, test with the default decode behavior, which will cause an
    // exception to be thrown.
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();
    final List<String> nonFatalDecodeMessages = new ArrayList<>();

    try
    {
      c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
      fail("Expected an exception from decodeEmbeddedControls with an object " +
           "that's not a valid generic control using the default behavior");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertTrue(nonFatalDecodeMessages.isEmpty());
    }


    // Change the behavior so that an unparsable object won't result in an
    // exception.
    behavior.setThrowOnUnparsableObject(false);

    List<Control> decodedControls =
         c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());

    assertFalse(nonFatalDecodeMessages.isEmpty());
    nonFatalDecodeMessages.clear();


    // Try again with the same behavior, but this time don't provide the
    // nonFatalDecodeMessages list.
    behavior.setThrowOnUnparsableObject(false);

    decodedControls = c.decodeEmbeddedControls(behavior, null);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());

    assertTrue(nonFatalDecodeMessages.isEmpty());
  }



  /**
   * Tests the behavior when trying to use the {@code decodeEmbeddedControls}
   * method with an object that has an unrecognized top-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEmbeddedControlsUnrecognizedTopLevelField()
         throws Exception
  {
    final JSONObject embeddedControlObject = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("criticality", false),
         new JSONField("unrecognized", "foo"));

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              embeddedControlObject);


    // First, test with the default decode behavior, which does not use strict
    // mode.  This should not result in an exception or a non-fatal message.
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();
    final List<String> nonFatalDecodeMessages = new ArrayList<>();

    List<Control> decodedControls =
         c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
    assertEquals(decodedControls.size(), 1);
    assertEquals(decodedControls.get(0).getOID(), "1.2.3.4");
    assertFalse(decodedControls.get(0).isCritical());
    assertNull(decodedControls.get(0).getValue());

    assertTrue(nonFatalDecodeMessages.isEmpty());


    // Change the default behavior to use strict mode and verify that
    // an exception is now thrown.
    behavior.setStrict(true);

    try
    {
      c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
      fail("Expected an exception from decodeEmbeddedControls with an object " +
           "that has an unrecognized field in strict mode.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertTrue(nonFatalDecodeMessages.isEmpty());
    }


    // Change the behavior so that an unparsable object won't result in an
    // exception.
    behavior.setThrowOnUnparsableObject(false);

    decodedControls =
         c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());

    assertFalse(nonFatalDecodeMessages.isEmpty());
    nonFatalDecodeMessages.clear();


    // Try again with the same behavior, but this time don't provide the
    // nonFatalDecodeMessages list.
    behavior.setThrowOnUnparsableObject(false);

    decodedControls = c.decodeEmbeddedControls(behavior, null);
    assertNotNull(decodedControls);
    assertTrue(decodedControls.isEmpty());

    assertTrue(nonFatalDecodeMessages.isEmpty());
  }



  /**
   * Tests the behavior when trying to use the {@code decodeEmbeddedControls}
   * method with an object that is a valid critical generic control but not a
   * valid specific control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEmbeddedControlsValidCriticalGenericInvalidSpecific()
         throws Exception
  {
    final JSONObject embeddedControlObject = new JSONObject(
         new JSONField("oid",
              RetainIdentityRequestControl.RETAIN_IDENTITY_REQUEST_OID),
         new JSONField("criticality", true),
         new JSONField("value-json", new JSONObject(
              new JSONField("invalid", "foo"))));

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              embeddedControlObject);


    // First, test with the default decode behavior, which will throw an
    // exception for an invalid critical control.
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();
    final List<String> nonFatalDecodeMessages = new ArrayList<>();

    try
    {
      c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
      fail("Expected an exception from decodeEmbeddedControls with an object " +
           "that has an unrecognized field in strict mode.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertTrue(nonFatalDecodeMessages.isEmpty());
    }


    // Change the default behavior so that it will not throw an exception for
    // an invalid critical control.  This should cause the method to return an
    // empty list of controls with a non-fatal message.
    behavior.setThrowOnInvalidCriticalControl(false);

    List<Control> decodedControls =
         c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
    assertTrue(decodedControls.isEmpty());

    assertFalse(nonFatalDecodeMessages.isEmpty());


    // Perform the same test, but don't provide the nonFatalDecodeMessages list.
    decodedControls = c.decodeEmbeddedControls(behavior, null);
    assertTrue(decodedControls.isEmpty());
  }



  /**
   * Tests the behavior when trying to use the {@code decodeEmbeddedControls}
   * method with an object that is a valid non-critical generic control but not
   * a valid specific control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeEmbeddedControlsValidNonCriticalGenericInvalidSpecific()
         throws Exception
  {
    final JSONObject embeddedControlObject = new JSONObject(
         new JSONField("oid",
              RetainIdentityRequestControl.RETAIN_IDENTITY_REQUEST_OID),
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("invalid", "foo"))));

    final JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControlObjects(true,
              embeddedControlObject);


    // First, test with the default decode behavior, which will throw an
    // exception for an invalid non-critical control.
    final JSONFormattedControlDecodeBehavior behavior =
         new JSONFormattedControlDecodeBehavior();
    final List<String> nonFatalDecodeMessages = new ArrayList<>();

    try
    {
      c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
      fail("Expected an exception from decodeEmbeddedControls with an object " +
           "that has an unrecognized field in strict mode.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertTrue(nonFatalDecodeMessages.isEmpty());
    }


    // Change the default behavior so that it will not throw an exception for
    // an invalid non-critical control.  This should cause the method to return
    // an empty list of controls with a non-fatal message.
    behavior.setThrowOnInvalidNonCriticalControl(false);

    List<Control> decodedControls =
         c.decodeEmbeddedControls(behavior, nonFatalDecodeMessages);
    assertTrue(decodedControls.isEmpty());

    assertFalse(nonFatalDecodeMessages.isEmpty());


    // Perform the same test, but don't provide the nonFatalDecodeMessages list.
    decodedControls = c.decodeEmbeddedControls(behavior, null);
    assertTrue(decodedControls.isEmpty());
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    c = (JSONFormattedRequestControl)
         Control.decodeJSONControl(controlObject, true, true);

    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getControlObjects());
    assertEquals(c.getControlObjects(),
         Arrays.asList(
              new JSONObject(
                   new JSONField("oid", gazRC.getOID()),
                   new JSONField("control-name", gazRC.getControlName()),
                   new JSONField("criticality", gazRC.isCritical()),
                   new JSONField("value-json", new JSONObject(
                        new JSONField("include-authentication-entry", true),
                        new JSONField("include-authorization-entry", true),
                        new JSONField("attributes", new JSONArray(
                             new JSONString("uid"),
                             new JSONString("givenName"),
                             new JSONString("sn"),
                             new JSONString("cn"),
                             new JSONString("mail")))))),
              new JSONObject(
                   new JSONField("oid", riRC.getOID()),
                   new JSONField("control-name", riRC.getControlName()),
                   new JSONField("criticality", riRC.isCritical()))));

    assertNotNull(c.getControlName());
    assertEquals(c.getControlName(), "JSON-Formatted Request Control");
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value doesn't include the controls element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingControlsElement()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    Control.decodeJSONControl(controlObject, true, true);
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value includes the controls element as an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueEmptyControlsElement()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("controls", JSONArray.EMPTY_ARRAY))));

    c = JSONFormattedRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(c);

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.64");

    assertTrue(c.isCritical());

    assertNotNull(c.getControlObjects());
    assertTrue(c.getControlObjects().isEmpty());
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value includes the controls element with an item that is not an
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlItemNotObject()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("controls", new JSONArray(
                   new JSONString("foo"))))));

    Control.decodeJSONControl(controlObject, true, true);
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value includes the controls element with an object that is a valid
   * generic control, but not a valid specific control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidGenericControl()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("controls", new JSONArray(
                   new JSONObject(
                        new JSONField("invalid", "foo")))))));

    Control.decodeJSONControl(controlObject, true, true);
  }



  /**
   * Tests the behavior of the {@code decodeJSONControl} method for a control
   * whose value includes an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedField()
         throws Exception
  {
    final GetAuthorizationEntryRequestControl gazRC =
         new GetAuthorizationEntryRequestControl(true, true, true, "uid",
              "givenName", "sn", "cn", "mail");

    final RetainIdentityRequestControl riRC =
         new RetainIdentityRequestControl();

    JSONFormattedRequestControl c =
         JSONFormattedRequestControl.createWithControls(true, gazRC, riRC);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("controls", new JSONArray(
                   new JSONObject(
                        new JSONField("oid", "1.2.3.4"),
                        new JSONField("criticality", false)))),
              new JSONField("unrecognized", "foo"))));

    try
    {
      JSONFormattedRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception when trying to decode a JSON object with " +
           "an unrecognized field in strict mode.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test again in non-strict mode and verify that it doesn't throw an
    // exception.
    JSONFormattedRequestControl.decodeJSONControl(controlObject, false);
  }



  /**
   * Tests the behavior when trying to decode a JSON-formatted request control
   * with an embedded JSON-formatted request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmbeddedJSONFormattedRequestControl()
         throws Exception
  {
    // Create controls to use for testing.
    final JSONFormattedRequestControl embeddedCriticalControl =
         JSONFormattedRequestControl.createEmptyControl(true);
    final JSONFormattedRequestControl embeddedNonCriticalControl =
         JSONFormattedRequestControl.createEmptyControl(false);

    final JSONFormattedRequestControl controlWithEmbeddedCriticalControl =
         JSONFormattedRequestControl.createWithControls(true,
              embeddedCriticalControl);
    final JSONFormattedRequestControl controlWithEmbeddedNonCriticalControl =
         JSONFormattedRequestControl.createWithControls(true,
              embeddedNonCriticalControl);


    // Create a decode behavior with the default settings.  Make sure that
    // embedded JSON-formatted controls are not allowed by default.
    final JSONFormattedControlDecodeBehavior decodeBehavior =
         new JSONFormattedControlDecodeBehavior();
    assertFalse(decodeBehavior.allowEmbeddedJSONFormattedControl());


    // Try to decode the embedded controls for a JSON-formatted request control
    // that has an embedded critical JSON-formatted request control.  This
    // should result in an exception.
    final List<String> nonFatalDecodeMessages = new ArrayList<>();
    try
    {
      controlWithEmbeddedCriticalControl.decodeEmbeddedControls(
           decodeBehavior, nonFatalDecodeMessages);
      fail("Expected an exception when trying to decode embedded controls " +
           "that included a critical JSON-formatted request control.");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
      assertTrue(nonFatalDecodeMessages.isEmpty());
    }


    // Try to decode the embedded controls for a JSON-formatted request control
    // that has an embedded non-critical JSON-formatted request control.  This
    // should cause the control to be ignored with a non-fatal decode error.
    List<Control> embeddedControls =
         controlWithEmbeddedNonCriticalControl.decodeEmbeddedControls(
              decodeBehavior, nonFatalDecodeMessages);
    assertTrue(embeddedControls.isEmpty());
    assertFalse(nonFatalDecodeMessages.isEmpty());
    nonFatalDecodeMessages.clear();


    // Change the decode behavior to allow embedded JSON-formatted request
    // controls.
    decodeBehavior.setAllowEmbeddedJSONFormattedControl(true);
    assertTrue(decodeBehavior.allowEmbeddedJSONFormattedControl());


    // Verify that we can now extract an embedded critical JSON-formatted
    // request control.
    embeddedControls =
         controlWithEmbeddedCriticalControl.decodeEmbeddedControls(
              decodeBehavior, nonFatalDecodeMessages);
    assertEquals(embeddedControls.size(), 1);
    assertEquals(embeddedControls.get(0).getOID(),
         JSONFormattedRequestControl.JSON_FORMATTED_REQUEST_OID);
    assertTrue(embeddedControls.get(0).isCritical());
    assertTrue(nonFatalDecodeMessages.isEmpty());


    // Verify that we can now extract an embedded non-critical JSON-formatted
    // request control.
    embeddedControls =
         controlWithEmbeddedNonCriticalControl.decodeEmbeddedControls(
              decodeBehavior, nonFatalDecodeMessages);
    assertEquals(embeddedControls.size(), 1);
    assertEquals(embeddedControls.get(0).getOID(),
         JSONFormattedRequestControl.JSON_FORMATTED_REQUEST_OID);
    assertFalse(embeddedControls.get(0).isCritical());
    assertTrue(nonFatalDecodeMessages.isEmpty());
  }
}
