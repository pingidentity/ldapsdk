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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.protocol.LDAPMessage;



/**
 * This class provides a set of test cases for the SearchRequest class.
 */
public class SearchRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);

    assertEquals(searchRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST);

    assertNull(searchRequest.getIntermediateResponseListener());
    searchRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(searchRequest.getIntermediateResponseListener());
    searchRequest.setIntermediateResponseListener(null);
    assertNull(searchRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor with attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)", "cn", "sn");
    searchRequest.setFollowReferrals(true);
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the second constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           Filter.create("(objectClass=*)"));
    searchRequest.setFollowReferrals(false);
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the second constructor with attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           Filter.create("(objectClass=*)"), "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the third constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoAttrsNoListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(null, "dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the third constructor with attributes and a listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithAttrsAndListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), "dc=example,dc=com",
                           SearchScope.BASE, "(objectClass=*)", "cn",
                           "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the fourth constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NoAttrsNoListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(null, "dc=example,dc=com", SearchScope.BASE,
                           Filter.create("(objectClass=*)"));
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the fourth constructor with attributes and a listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4WithAttrsAndListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), "dc=example,dc=com",
                           SearchScope.BASE, Filter.create("(objectClass=*)"),
                           "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.BASE);
    assertEquals(searchRequest.getDereferencePolicy(), DereferencePolicy.NEVER);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertFalse(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the fifth constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NoAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           "(objectClass=*)");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the fifth constructor with attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5WithAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           "(objectClass=*)", "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the sixth constructor with no attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NoAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           Filter.create("(objectClass=*)"));
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the sixth constructor with attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6WithAttrs()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           Filter.create("(objectClass=*)"), "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the seventh constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NoAttrsNoListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(null, "dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           "(objectClass=*)");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the seventh constructor with attributes and a search result listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7WithAttrsAndListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), "dc=example,dc=com",
                           SearchScope.SUB, DereferencePolicy.ALWAYS,
                           1234, 5678, true, "(objectClass=*)", "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the eighth constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NoAttrsNoListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(null, "dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           Filter.create("(objectClass=*)"));
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the eighth constructor with attributes and a search result listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8WithAttrsAndListener()
         throws Exception
  {
    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), "dc=example,dc=com",
                           SearchScope.SUB, DereferencePolicy.ALWAYS,
                           1234, 5678, true, Filter.create("(objectClass=*)"),
                           "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertFalse(searchRequest.hasControl());
    assertFalse(searchRequest.hasControl("1.2.3.4"));
    assertNull(searchRequest.getControl("1.2.3.4"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 0);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the ninth constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9NoAttrsNoListener()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchRequest searchRequest =
         new SearchRequest(null, controls, "dc=example,dc=com",
                           SearchScope.SUB, DereferencePolicy.ALWAYS,
                           1234, 5678, true, "(objectClass=*)");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertTrue(searchRequest.hasControl());
    assertTrue(searchRequest.hasControl("1.2.3.4"));
    assertNotNull(searchRequest.getControl("1.2.3.4"));
    assertFalse(searchRequest.hasControl("1.2.3.6"));
    assertNull(searchRequest.getControl("1.2.3.6"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 2);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the ninth constructor with attributes and a search result listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9WithAttrsAndListener()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), controls,
                           "dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, 1234, 5678, true,
                           "(objectClass=*)", "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 1234);
    assertEquals(searchRequest.getTimeLimitSeconds(), 5678);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertTrue(searchRequest.hasControl());
    assertTrue(searchRequest.hasControl("1.2.3.4"));
    assertNotNull(searchRequest.getControl("1.2.3.4"));
    assertFalse(searchRequest.hasControl("1.2.3.6"));
    assertNull(searchRequest.getControl("1.2.3.6"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 2);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the tenth constructor with no attributes and no listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10NoAttrsNoListener()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchRequest searchRequest =
         new SearchRequest(null, controls, "dc=example,dc=com",
                           SearchScope.SUB, DereferencePolicy.ALWAYS,
                           -1234, -5678, true,
                           Filter.create("(objectClass=*)"));
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 0);

    assertNotNull(searchRequest.getAttributeList());
    assertTrue(searchRequest.getAttributeList().isEmpty());

    assertNull(searchRequest.getSearchResultListener());

    assertTrue(searchRequest.hasControl());
    assertTrue(searchRequest.hasControl("1.2.3.4"));
    assertNotNull(searchRequest.getControl("1.2.3.4"));
    assertFalse(searchRequest.hasControl("1.2.3.6"));
    assertNull(searchRequest.getControl("1.2.3.6"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 2);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the tenth constructor with attributes and a search result listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10WithAttrsAndListener()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    SearchRequest searchRequest =
         new SearchRequest(new TestSearchResultListener(), controls,
                           "dc=example,dc=com", SearchScope.SUB,
                           DereferencePolicy.ALWAYS, -1234, -5678, true,
                           Filter.create("(objectClass=*)"), "cn", "sn");
    searchRequest = searchRequest.duplicate();

    assertNotNull(searchRequest.getBaseDN());
    assertEquals(searchRequest.getBaseDN(), "dc=example,dc=com");

    assertEquals(searchRequest.getScope(), SearchScope.SUB);
    assertEquals(searchRequest.getDereferencePolicy(),
                 DereferencePolicy.ALWAYS);
    assertEquals(searchRequest.getSizeLimit(), 0);
    assertEquals(searchRequest.getTimeLimitSeconds(), 0);
    assertTrue(searchRequest.typesOnly());

    assertNotNull(searchRequest.getFilter());
    assertEquals(searchRequest.getFilter().toString(), "(objectClass=*)");

    assertNotNull(searchRequest.getAttributes());
    assertEquals(searchRequest.getAttributes().length, 2);

    assertNotNull(searchRequest.getAttributeList());
    assertFalse(searchRequest.getAttributeList().isEmpty());
    assertEquals(searchRequest.getAttributeList().size(), 2);

    assertNotNull(searchRequest.getSearchResultListener());

    assertTrue(searchRequest.hasControl());
    assertTrue(searchRequest.hasControl("1.2.3.4"));
    assertNotNull(searchRequest.getControl("1.2.3.4"));
    assertFalse(searchRequest.hasControl("1.2.3.6"));
    assertNull(searchRequest.getControl("1.2.3.6"));
    assertNotNull(searchRequest.getControls());
    assertEquals(searchRequest.getControls().length, 2);

    assertNotNull(searchRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    searchRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    searchRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(searchRequest);
  }



  /**
   * Tests the {@code getBaseDN} and {@code setBaseDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetBaseDN()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getBaseDN(), "dc=example,dc=com");

    r.setBaseDN("o=example.com");
    assertEquals(r.getBaseDN(), "o=example.com");

    r.setBaseDN(new DN("o=example.net"));
    assertEquals(r.getBaseDN(), "o=example.net");

    testEncoding(r);
  }



  /**
   * Tests the {@code getScope} and {@code setScope} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetScope()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getScope(), SearchScope.BASE);

    r.setScope(SearchScope.ONE);
    assertEquals(r.getScope(), SearchScope.ONE);

    testEncoding(r);
  }



  /**
   * Tests the {@code DereferencePolicy} and {@code setDereferencePolicy}
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDerefPolicy()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getDereferencePolicy(), DereferencePolicy.NEVER);

    r.setDerefPolicy(DereferencePolicy.SEARCHING);
    assertEquals(r.getDereferencePolicy(), DereferencePolicy.SEARCHING);

    testEncoding(r);
  }



  /**
   * Tests the {@code getSizeLimit} and {@code setSizeLimit} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetSizeLimit()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getSizeLimit(), 0);

    r.setSizeLimit(1);
    assertEquals(r.getSizeLimit(), 1);

    r.setSizeLimit(-1);
    assertEquals(r.getSizeLimit(), 0);

    testEncoding(r);
  }



  /**
   * Tests the {@code getTimeLimit} and {@code setTimeLimit} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndsetTimeLimitSeconds()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getTimeLimitSeconds(), 0);

    r.setTimeLimitSeconds(1);
    assertEquals(r.getTimeLimitSeconds(), 1);

    r.setTimeLimitSeconds(-1);
    assertEquals(r.getTimeLimitSeconds(), 0);

    testEncoding(r);
  }



  /**
   * Tests the {@code getTypesOnly} and {@code setTypesOnly} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetTypesOnly()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertFalse(r.typesOnly());

    r.setTypesOnly(true);
    assertTrue(r.typesOnly());

    testEncoding(r);
  }



  /**
   * Tests the {@code getFilter} and {@code setFilter} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetFilter()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getFilter().toString(), "(objectClass=*)");

    r.setFilter("(uid=john.doe)");
    assertEquals(r.getFilter().toString(), "(uid=john.doe)");

    r.setFilter(Filter.createEqualityFilter("cn", "John Doe"));
    assertEquals(r.getFilter().toString(), "(cn=John Doe)");

    testEncoding(r);
  }



  /**
   * Tests the {@code getAttributes} and {@code setAttributes} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetAttributes()
         throws Exception
  {
    SearchRequest r =
         new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                           "(objectClass=*)");
    assertEquals(r.getAttributes().length, 0);
    assertTrue(r.getAttributeList().isEmpty());

    r.setAttributes("givenName", "sn");
    assertEquals(r.getAttributes().length, 2);
    assertFalse(r.getAttributeList().isEmpty());

    r.setAttributes((String[]) null);
    assertEquals(r.getAttributes().length, 0);
    assertTrue(r.getAttributeList().isEmpty());

    r.setAttributes(new String[] { "1.1" });
    assertEquals(r.getAttributes().length, 1);
    assertFalse(r.getAttributeList().isEmpty());

    r.setAttributes((ArrayList<String>) null);
    assertEquals(r.getAttributes().length, 0);
    assertTrue(r.getAttributeList().isEmpty());

    ArrayList<String> attrList = new ArrayList<String>();
    attrList.add("uid");
    attrList.add("givenName");
    attrList.add("cn");
    attrList.add("sn");
    r.setAttributes(attrList);
    assertEquals(r.getAttributes().length, 4);
    assertFalse(r.getAttributeList().isEmpty());

    testEncoding(r);
  }



  /**
   * Tests to ensure that the encoding for the provided search request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  searchRequest  The search request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final SearchRequest searchRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = searchRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    searchRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
