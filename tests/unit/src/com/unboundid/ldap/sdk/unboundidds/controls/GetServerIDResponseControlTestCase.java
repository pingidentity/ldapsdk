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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * {@code GetServerIDResponseControl} class.
 */
public class GetServerIDResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralControl()
         throws Exception
  {
    final String serverID = CryptoHelper.getRandomUUID().toString();

    GetServerIDResponseControl c = new GetServerIDResponseControl(serverID);
    c = new GetServerIDResponseControl().decodeControl(c.getOID(),
         c.isCritical(),c.getValue());

    assertFalse(c.isCritical());

    assertNotNull(c.getServerID());
    assertEquals(c.getServerID(), serverID);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new GetServerIDResponseControl().decodeControl(
         GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID, false, null);
  }



  /**
   * Tests the {@code get} method with a result that does not contain a get
   * server ID response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPResultMissing()
         throws Exception
  {
    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPResultValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new GetServerIDResponseControl("foo")
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPResultValidGenericType()
         throws Exception
  {
    final Control tmp = new GetServerIDResponseControl("foo");

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetLDAPResultInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID, false,
           null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    GetServerIDResponseControl.get(r);
  }



  /**
   * Tests the {@code get} method with a result that does not contain a get
   * server ID response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchEntryMissing()
         throws Exception
  {
    final SearchResultEntry e = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(e);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchEntryValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new GetServerIDResponseControl("foo")
    };

    final SearchResultEntry e = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(e);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchEntryValidGenericType()
         throws Exception
  {
    final Control tmp = new GetServerIDResponseControl("foo");

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(e);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetSearchEntryInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID, false,
           null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         controls);

    GetServerIDResponseControl.get(e);
  }



  /**
   * Tests the {@code get} method with a result that does not contain a get
   * server ID response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchReferenceMissing()
         throws Exception
  {
    final SearchResultReference r = new SearchResultReference(
         new String[] { "ldap://server.example.com:389/dc=example,dc=com" },
         null);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchReferenceValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new GetServerIDResponseControl("foo")
    };

    final SearchResultReference r = new SearchResultReference(
         new String[] { "ldap://server.example.com:389/dc=example,dc=com" },
         controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSearchReferenceValidGenericType()
         throws Exception
  {
    final Control tmp = new GetServerIDResponseControl("foo");

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultReference r = new SearchResultReference(
         new String[] { "ldap://server.example.com:389/dc=example,dc=com" },
         controls);

    final GetServerIDResponseControl c = GetServerIDResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getServerID(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a get server ID response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetSearchReferenceInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID, false,
           null)
    };

    final SearchResultReference r = new SearchResultReference(
         new String[] { "ldap://server.example.com:389/dc=example,dc=com" },
         controls);

    GetServerIDResponseControl.get(r);
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
    final GetServerIDResponseControl c =
         new GetServerIDResponseControl("this-is-the-server-id");

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
              new JSONField("server-id", "this-is-the-server-id")));


    GetServerIDResponseControl decodedControl =
         GetServerIDResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");


    decodedControl =
         (GetServerIDResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");
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
    final GetServerIDResponseControl c =
         new GetServerIDResponseControl("this-is-the-server-id");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetServerIDResponseControl decodedControl =
         GetServerIDResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");


    decodedControl =
         (GetServerIDResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the required server-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingServerID()
          throws Exception
  {
    final GetServerIDResponseControl c =
         new GetServerIDResponseControl("this-is-the-server-id");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));


    GetServerIDResponseControl.decodeJSONControl(controlObject, true);
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
    final GetServerIDResponseControl c =
         new GetServerIDResponseControl("this-is-the-server-id");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "this-is-the-server-id"),
              new JSONField("unrecognized","foo"))));


    GetServerIDResponseControl.decodeJSONControl(controlObject, true);
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
    final GetServerIDResponseControl c =
         new GetServerIDResponseControl("this-is-the-server-id");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("server-id", "this-is-the-server-id"),
              new JSONField("unrecognized","foo"))));


    GetServerIDResponseControl decodedControl =
         GetServerIDResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");


    decodedControl =
         (GetServerIDResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getServerID(), "this-is-the-server-id");
  }
}
