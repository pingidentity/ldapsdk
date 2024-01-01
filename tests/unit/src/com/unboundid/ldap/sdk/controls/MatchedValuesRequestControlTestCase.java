/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
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
 * This class provides a set of test cases for the MatchedValuesRequestControl
 * class.
 */
public class MatchedValuesRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a valid single matched values filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Single()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createPresentFilter("objectClass");

    MatchedValuesRequestControl c = new MatchedValuesRequestControl(f);
    c = new MatchedValuesRequestControl(c);

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getFilters());
    assertEquals(c.getFilters().length, 1);
    assertEquals(c.getFilters()[0].toString(),
                 "(objectClass=*)");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a valid set of matched values filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Multiple()
         throws Exception
  {
    MatchedValuesFilter[] filters =
    {
      MatchedValuesFilter.createPresentFilter("objectClass"),
      MatchedValuesFilter.createEqualityFilter("dc", "example")
    };

    MatchedValuesRequestControl c = new MatchedValuesRequestControl(filters);
    c = new MatchedValuesRequestControl(c);

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getFilters());
    assertEquals(c.getFilters().length, 2);
    assertEquals(c.getFilters()[0].toString(),
                 "(objectClass=*)");
    assertEquals(c.getFilters()[1].toString(),
                 "(dc=example)");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with an empty set of matched values filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoFilters()
         throws Exception
  {
    new MatchedValuesRequestControl();
  }



  /**
   * Tests the second constructor with a valid single matched values filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Single()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createPresentFilter("objectClass");

    MatchedValuesRequestControl c = new MatchedValuesRequestControl(true, f);
    c = new MatchedValuesRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getFilters());
    assertEquals(c.getFilters().length, 1);
    assertEquals(c.getFilters()[0].toString(),
                 "(objectClass=*)");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a valid set of matched values filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Multiple()
         throws Exception
  {
    MatchedValuesFilter[] filters =
    {
      MatchedValuesFilter.createPresentFilter("objectClass"),
      MatchedValuesFilter.createEqualityFilter("dc", "example")
    };

    MatchedValuesRequestControl c =
         new MatchedValuesRequestControl(true, filters);
    c = new MatchedValuesRequestControl(c);

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getFilters());
    assertEquals(c.getFilters().length, 2);
    assertEquals(c.getFilters()[0].toString(),
                 "(objectClass=*)");
    assertEquals(c.getFilters()[1].toString(),
                 "(dc=example)");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with an empty set of matched values filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NoFilters()
         throws Exception
  {
    new MatchedValuesRequestControl(true);
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
    Control c =
         new Control(MatchedValuesRequestControl.MATCHED_VALUES_REQUEST_OID,
                     true, null);
    new MatchedValuesRequestControl(c);
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
    Control c =
         new Control(MatchedValuesRequestControl.MATCHED_VALUES_REQUEST_OID,
                     true, new ASN1OctetString("foo"));
    new MatchedValuesRequestControl(c);
  }



  /**
   * Tests the constructor that takes a list of matched values filters rather
   * than an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithFilterList()
         throws Exception
  {
    MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         Arrays.asList(
              MatchedValuesFilter.createEqualityFilter("objectClass", "person"),
              MatchedValuesFilter.createEqualityFilter("objectClass", "user")));

    c = new MatchedValuesRequestControl(c);

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getFilters());
    assertEquals(c.getFilters().length, 2);
    assertEquals(c.getFilters()[0].toString(),
                 "(objectClass=person)");
    assertEquals(c.getFilters()[1].toString(),
                 "(objectClass=user)");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Sends a search request to the server containing the matched values request
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithMatchedValuesControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    SearchRequest searchRequest =
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)");
    searchRequest.addControl(new MatchedValuesRequestControl(true,
         MatchedValuesFilter.createPresentFilter("objectclass")));

    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    conn.close();
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
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

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
              new JSONField("filters", new JSONArray(
                   new JSONString("(attr1=value1)"),
                   new JSONString("(attr2=value2)")))));


    MatchedValuesRequestControl decodedControl =
         MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());


    decodedControl =
         (MatchedValuesRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());
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
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    MatchedValuesRequestControl decodedControl =
         MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());


    decodedControl =
         (MatchedValuesRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the required filters element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingFilters()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an empty filters element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueEmptyFilters()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", JSONArray.EMPTY_ARRAY))));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a filters value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueFilterNotString()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", new JSONArray(
                   new JSONNumber(1234))))));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a filters value that is not a valid LDAP filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNotLDAPFilter()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", new JSONArray(
                   new JSONString("not-a-valid-ldap-filter"))))));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a filters value that is a valid LDAP filter but not a valid
   * matched values filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNotMatchedValuesFilter()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", new JSONArray(
                   new JSONString("(&(givenName=John)(sn=Doe))"))))));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value an unrecognized element in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", new JSONArray(
                   new JSONString("(attr1=value1)"),
                   new JSONString("(attr2=value2)"))),
              new JSONField("unrecognized", "foo"))));

    MatchedValuesRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value an unrecognized element in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNOnStrict()
          throws Exception
  {
    final MatchedValuesRequestControl c = new MatchedValuesRequestControl(
         false,
         MatchedValuesFilter.createEqualityFilter("attr1", "value1"),
         MatchedValuesFilter.createEqualityFilter("attr2", "value2"));

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("filters", new JSONArray(
                   new JSONString("(attr1=value1)"),
                   new JSONString("(attr2=value2)"))),
              new JSONField("unrecognized", "foo"))));


    MatchedValuesRequestControl decodedControl =
         MatchedValuesRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());


    decodedControl =
         (MatchedValuesRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getFilters().length, 2);
    assertEquals(decodedControl.getFilters()[0].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr1",
              "value1").toFilter());
    assertEquals(decodedControl.getFilters()[1].toFilter(),
         MatchedValuesFilter.createEqualityFilter("attr2",
              "value2").toFilter());
  }
}
