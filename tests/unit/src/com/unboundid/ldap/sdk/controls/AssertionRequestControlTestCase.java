/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
}
