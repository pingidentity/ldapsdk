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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the AssertionRequestControl
 * class.
 */
public class AssertionRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a valid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    AssertionRequestControl c =
         new AssertionRequestControl("(objectClass=*)");
    c = new AssertionRequestControl(c);

    assertNotNull(c);
    assertEquals(c.getFilter().toString(), "(objectClass=*)");

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with an invalid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor1InvalidFilter()
         throws Exception
  {
    new AssertionRequestControl("(invalid)");
  }



  /**
   * Tests the second constructor with a valid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    AssertionRequestControl c =
         new AssertionRequestControl(
                  Filter.createPresenceFilter("objectClass"));
    c = new AssertionRequestControl(c);

    assertNotNull(c);
    assertEquals(c.getFilter().toString(), "(objectClass=*)");

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a valid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    AssertionRequestControl c =
         new AssertionRequestControl("(objectClass=*)", false);
    c = new AssertionRequestControl(c);

    assertNotNull(c);
    assertEquals(c.getFilter().toString(), "(objectClass=*)");

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with an invalid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidFilter()
         throws Exception
  {
    new AssertionRequestControl("(invalid)", false);
  }



  /**
   * Tests the fourth constructor with a valid search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    AssertionRequestControl c =
         new AssertionRequestControl(
                  Filter.createPresenceFilter("objectClass"), false);
    c = new AssertionRequestControl(c);

    assertNotNull(c);
    assertEquals(c.getFilter().toString(), "(objectClass=*)");

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a generic control that does not contain a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testConstructor5NoValue()
         throws Exception
  {
    Control c = new Control(AssertionRequestControl.ASSERTION_REQUEST_OID,
                            true, null);
    new AssertionRequestControl(c);
  }



  /**
   * Tests the fifth constructor with a control whose value is not a valid
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class})
  public void testConstructor5ValueNotFilter()
         throws Exception
  {
    Control c = new Control(AssertionRequestControl.ASSERTION_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new AssertionRequestControl(c);
  }



  /**
   * Tests the {@code generate} method when one single-valued attribute is
   * specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithOneSingleValuedAttribute()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c = AssertionRequestControl.generate(e, "dc");
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createEqualityFilter("dc", "example"));
  }



  /**
   * Tests the {@code generate} method when one multi-valued attribute is
   * specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithOneMultiValuedAttribute()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c =
         AssertionRequestControl.generate(e, "description");
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createANDFilter(
         Filter.createEqualityFilter("description", "foo"),
         Filter.createEqualityFilter("description", "bar")));
  }



  /**
   * Tests the {@code generate} method when multiple attributes are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithMultipleAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c =
         AssertionRequestControl.generate(e, "dc", "description", "missing");
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createANDFilter(
         Filter.createEqualityFilter("dc", "example"),
         Filter.createEqualityFilter("description", "foo"),
         Filter.createEqualityFilter("description", "bar")));
  }



  /**
   * Tests the {@code generate} method when the only attributes specified don't
   * exist in the provided entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithOnlyMissingAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c =
         AssertionRequestControl.generate(e, "missing1", "missing2");
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createANDFilter());
  }



  /**
   * Tests the {@code generate} method when no attributes are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithoutAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c = AssertionRequestControl.generate(e);
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createANDFilter(
         Filter.createEqualityFilter("objectClass", "top"),
         Filter.createEqualityFilter("objectClass", "domain"),
         Filter.createEqualityFilter("dc", "example"),
         Filter.createEqualityFilter("description", "foo"),
         Filter.createEqualityFilter("description", "bar")));
  }



  /**
   * Tests the {@code generate} method when the attribute set is {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateWithNullAttributes()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo",
         "description: bar");

    final AssertionRequestControl c =
         AssertionRequestControl.generate(e, (String[]) null);
    assertNotNull(c);

    final Filter f = c.getFilter();
    assertNotNull(f);
    assertEquals(f, Filter.createANDFilter(
         Filter.createEqualityFilter("objectClass", "top"),
         Filter.createEqualityFilter("objectClass", "domain"),
         Filter.createEqualityFilter("dc", "example"),
         Filter.createEqualityFilter("description", "foo"),
         Filter.createEqualityFilter("description", "bar")));
  }



  /**
   * Sends a search request to the server with an assertion control that
   * contains a matching filter.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithMatchingControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.BASE,
                           "(objectClass=*)");
    searchRequest.addControl(new AssertionRequestControl("(objectClass=top)"));
    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Sends a search request to the server with an assertion control that
   * contains a non-matching filter.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithNonMatchingControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.BASE,
                           "(objectClass=*)");
    searchRequest.addControl(
         new AssertionRequestControl("(description=not found)"));
    try
    {
      conn.search(searchRequest);
      fail("Expected assertion failed result when searching with the LDAP " +
            "assertion control.");
    }
    catch (LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.ASSERTION_FAILED);
    }

    conn.delete(getTestBaseDN());
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
    final Filter filter = Filter.createEqualityFilter("objectClass", "person");

    final AssertionRequestControl c = new AssertionRequestControl(filter, true);

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

    assertNull(controlObject.getFieldAsString("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 1);

    assertEquals(valueObject.getFieldAsString("filter"),
         filter.toString());


    AssertionRequestControl decodedControl =
         AssertionRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertEquals(decodedControl.getFilter(), filter);


    decodedControl =
         (AssertionRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertEquals(decodedControl.getFilter(), filter);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a
   * base64-encoded representation of the control value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlWithValueBase64()
         throws Exception
  {
    final Filter filter = Filter.createEqualityFilter("objectClass", "person");

    final AssertionRequestControl c = new AssertionRequestControl(filter, true);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", false),
         new JSONField("value-base64",
              Base64.encode(c.getValue().getValue())));

    final AssertionRequestControl decodedControl =
         AssertionRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getFilter(), filter);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a
   * JSON-encoded representation of the control value when no filter is
   * provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueWithoutFilter()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.3.6.1.1.12"),
         new JSONField("criticality", false),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));

    AssertionRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a
   * JSON-encoded representation of the control value when a malformed filter
   * is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueWithMalformedFilter()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.3.6.1.1.12"),
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("filter", "malformed"))));

    AssertionRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a
   * JSON-encoded representation of the control value when the value object
   * contains an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJSONValueUnrecognizedFieldStrictMode()
         throws Exception
  {
    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.3.6.1.1.12"),
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("filter", "(objectClass=person)"),
              new JSONField("unrecognized", "unrecognized"))));

    AssertionRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object with a
   * JSON-encoded representation of the control value when the value object
   * contains an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlJSONValueUnrecognizedFieldNonStrictMode()
         throws Exception
  {
    final Filter filter = Filter.createEqualityFilter("objectClass", "person");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", "1.3.6.1.1.12"),
         new JSONField("criticality", false),
         new JSONField("value-json", new JSONObject(
              new JSONField("filter", filter.toString()),
              new JSONField("unrecognized", "unrecognized"))));


    final AssertionRequestControl decodedControl =
         AssertionRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), "1.3.6.1.1.12");

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getFilter(), filter);
  }
}
