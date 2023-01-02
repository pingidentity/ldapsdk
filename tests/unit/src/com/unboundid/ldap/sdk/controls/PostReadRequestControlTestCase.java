/*
 * Copyright 2007-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2023 Ping Identity Corporation
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
 * Copyright (C) 2007-2023 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the PostReadRequestControl class.
 */
public class PostReadRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null}, non-empty set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PostReadRequestControl c =
         new PostReadRequestControl("cn", "sn");
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 2);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Null()
         throws Exception
  {
    PostReadRequestControl c = new PostReadRequestControl((String[]) null);
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with an empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Empty()
         throws Exception
  {
    PostReadRequestControl c = new PostReadRequestControl(new String[0]);
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a non-{@code null}, non-empty set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    PostReadRequestControl c =
         new PostReadRequestControl(true, "cn", "sn");
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 2);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Null()
         throws Exception
  {
    PostReadRequestControl c = new PostReadRequestControl(false,
                                                          (String[]) null);
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with an empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Empty()
         throws Exception
  {
    PostReadRequestControl c = new PostReadRequestControl(false, new String[0]);
    c = new PostReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a generic control that does not contain a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    Control c = new Control(PostReadRequestControl.POST_READ_REQUEST_OID,
                            true, null);
    new PostReadRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValue()
         throws Exception
  {
    Control c = new Control(PostReadRequestControl.POST_READ_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new PostReadRequestControl(c);
  }



  /**
   * Adds an entry with the post-read request control and ensures that the
   * corresponding response control is included in the response.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithPostReadControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    Control[] controls =
    {
      new PostReadRequestControl((String[]) null)
    };

    LDAPConnection conn = getAdminConnection();

    LDAPResult addResult =
         conn.add(new AddRequest(getTestBaseDN(), getBaseEntryAttributes(),
                                 controls));

    boolean hasControl = false;
    for (Control c : addResult.getResponseControls())
    {
      if (c instanceof PostReadResponseControl)
      {
        hasControl = true;
        PostReadResponseControl prrc = (PostReadResponseControl) c;
        assertNotNull(prrc.getEntry());
        assertEquals(prrc.getEntry().getDN(), getTestBaseDN());
      }
      else if (c.getOID().equals(PostReadResponseControl.
                                      POST_READ_RESPONSE_OID))
      {
        fail("Failed to decode a response control with the appropriate " +
             "OID as a post-read response.");
      }
    }

    conn.delete(getTestBaseDN());
    conn.close();
    assertTrue(hasControl);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there are no requested attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNoAttributes()
          throws Exception
  {
    final PostReadRequestControl c = new PostReadRequestControl(false);

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


    PostReadRequestControl decodedControl =
         PostReadRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes().length, 0);


    decodedControl =
         (PostReadRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes().length, 0);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when there are requested attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributes()
          throws Exception
  {
    final PostReadRequestControl c = new PostReadRequestControl(false, "uid",
         "givenName", "sn", "cn", "mail");

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
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail")))));


    PostReadRequestControl decodedControl =
         PostReadRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (PostReadRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });
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
    final PostReadRequestControl c = new PostReadRequestControl(false, "uid",
         "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    PostReadRequestControl decodedControl =
         PostReadRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (PostReadRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains a non-string attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNonStringAttribute()
          throws Exception
  {
    final PostReadRequestControl c = new PostReadRequestControl(false, "uid",
         "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attributes", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))))));

    PostReadRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final PostReadRequestControl c = new PostReadRequestControl(false, "uid",
         "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))),
              new JSONField("unrecognized", "foo"))));


    PostReadRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final PostReadRequestControl c = new PostReadRequestControl(false, "uid",
         "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))),
              new JSONField("unrecognized", "foo"))));


    PostReadRequestControl decodedControl =
         PostReadRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (PostReadRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });
  }
}
