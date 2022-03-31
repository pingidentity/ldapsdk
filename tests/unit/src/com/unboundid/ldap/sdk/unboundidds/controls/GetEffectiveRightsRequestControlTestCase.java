/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the
 * {@code GetEffectiveRightsRequestControl} class.
 */
public class GetEffectiveRightsRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoAttributes()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(authzID);
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a single attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1SingleAttribute()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(authzID, "cn");
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 1);
    assertEquals(c.getAttributes()[0], "cn");

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with multiple attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1MultipleAttributes()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(authzID, "cn", "sn", "uid");
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 3);
    assertEquals(c.getAttributes()[0], "cn");
    assertEquals(c.getAttributes()[1], "sn");
    assertEquals(c.getAttributes()[2], "uid");

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} authorization ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAuthzID()
  {
    new GetEffectiveRightsRequestControl((String) null);
  }



  /**
   * Tests the second constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoAttributes()
         throws Exception
  {
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(true, authzID);
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertTrue(c.isCritical());

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
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(true, authzID, "cn");
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 1);
    assertEquals(c.getAttributes()[0], "cn");

    assertTrue(c.isCritical());

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
    String authzID = "dn:uid=test.user,ou=People,dc=example,dc=com";
    GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(true, authzID, "cn", "sn", "uid");
    c = new GetEffectiveRightsRequestControl(c);

    assertNotNull(c.getAuthzID());
    assertEquals(c.getAuthzID(), authzID);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 3);
    assertEquals(c.getAttributes()[0], "cn");
    assertEquals(c.getAttributes()[1], "sn");
    assertEquals(c.getAttributes()[2], "uid");

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} authorization ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullAuthzID()
  {
    new GetEffectiveRightsRequestControl(true, null);
  }



  /**
   * Tests the third constructor with a generic control that has no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    Control c = new Control(
         GetEffectiveRightsRequestControl.GET_EFFECTIVE_RIGHTS_REQUEST_OID,
         true, null);
    new GetEffectiveRightsRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    Control c = new Control(
         GetEffectiveRightsRequestControl.GET_EFFECTIVE_RIGHTS_REQUEST_OID,
         true, new ASN1OctetString("foo"));
    new GetEffectiveRightsRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control whose value is an empty
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueEmptySequence()
         throws Exception
  {
    Control c = new Control(
         GetEffectiveRightsRequestControl.GET_EFFECTIVE_RIGHTS_REQUEST_OID,
         true, new ASN1OctetString(new ASN1Sequence().encode()));
    new GetEffectiveRightsRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control whose value sequence
   * contains an invalid second element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalid()
         throws Exception
  {
    ASN1OctetString[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };

    Control c = new Control(
         GetEffectiveRightsRequestControl.GET_EFFECTIVE_RIGHTS_REQUEST_OID,
         true, new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new GetEffectiveRightsRequestControl(c);
  }



  /**
   * Sends a search request to the server with a get effective rights request
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithGetEffectiveRightsControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    Control[] controls =
    {
      new GetEffectiveRightsRequestControl(true, "dn:" + getTestBindDN())
    };

    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.BASE,
                           "(objectClass=*)");
    searchRequest.setControls(controls);

    try
    {
      SearchResult result = conn.search(searchRequest);

      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertEquals(result.getEntryCount(), 1);
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}
    }

    conn.close();
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object that does not include any attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutAttributes()
          throws Exception
  {
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe");

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
    assertEquals(valueObject.getFields().size(), 1);

    assertEquals(valueObject.getFieldAsString("authorization-id"), "u:jdoe");

    assertNull(valueObject.getFieldAsArray("attributes"));


    GetEffectiveRightsRequestControl decodedControl =
         GetEffectiveRightsRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes().length, 0);


    decodedControl =
         (GetEffectiveRightsRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes().length, 0);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object that includes a set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributes()
          throws Exception
  {
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
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

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 2);

    assertEquals(valueObject.getFieldAsString("authorization-id"), "u:jdoe");

    assertEquals(valueObject.getFieldAsArray("attributes"), Arrays.asList(
         new JSONString("uid"), new JSONString("givenName"),
         new JSONString("sn"), new JSONString("cn"), new JSONString("mail")));


    GetEffectiveRightsRequestControl decodedControl =
         GetEffectiveRightsRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (GetEffectiveRightsRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

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
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
              "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    GetEffectiveRightsRequestControl decodedControl =
         GetEffectiveRightsRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (GetEffectiveRightsRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the required authorization-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingAuthorizationID()
          throws Exception
  {
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
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
                   new JSONString("mail"))))));

    GetEffectiveRightsRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a non-string value in the set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueAttributeNotString()
          throws Exception
  {
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
              "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("authorization-id", "u:jdoe"),
              new JSONField("attributes", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))))));

    GetEffectiveRightsRequestControl.decodeJSONControl(controlObject, true);
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
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
              "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("authorization-id", "u:jdoe"),
              new JSONField("unrecognized", "foo"),
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))))));

    GetEffectiveRightsRequestControl.decodeJSONControl(controlObject, true);
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
    final GetEffectiveRightsRequestControl c =
         new GetEffectiveRightsRequestControl(false, "u:jdoe", "uid",
              "givenName", "sn", "cn", "mail");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("authorization-id", "u:jdoe"),
              new JSONField("unrecognized", "foo"),
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))))));


    GetEffectiveRightsRequestControl decodedControl =
         GetEffectiveRightsRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });


    decodedControl =
         (GetEffectiveRightsRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getAuthzID(), "u:jdoe");

    assertEquals(decodedControl.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });
  }
}
