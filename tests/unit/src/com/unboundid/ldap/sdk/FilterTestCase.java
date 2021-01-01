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



import java.io.ByteArrayInputStream;
import java.util.ArrayList;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.jsonfilter.EqualsJSONObjectFilter;
import com.unboundid.ldap.sdk.unboundidds.jsonfilter.JSONObjectFilter;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.util.StaticUtils.toUTF8String;



/**
 * This class provides a set of test cases for the Filter class.
 */
public class FilterTestCase
       extends LDAPSDKTestCase
{
  // The directory server schema, if available.
  private Schema schema;



  /**
   * Attempts to get the directory server schema, if it's available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void getSchema()
         throws Exception
  {
    schema = getTestDS().getSchema();
  }




  /**
   * Tests the {@code createANDFilter} method with an empty array (i.e., an
   * "LDAP TRUE" filter).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterEmptyArray()
         throws Exception
  {
    Filter f = Filter.createANDFilter(new Filter[0]);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterSingleElementArray()
         throws Exception
  {
    Filter[] filterElements =
    {
      Filter.create("(foo=bar)")
    };

    Filter f = Filter.createANDFilter(filterElements);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 1);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&(foo=bar))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterMultiElementArray()
         throws Exception
  {
    Filter[] filterElements =
    {
      Filter.create("(a=b)"),
      Filter.create("(c=d)"),
      Filter.create("(e=f)"),
    };

    Filter f = Filter.createANDFilter(filterElements);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 3);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&(a=b)(c=d)(e=f))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateANDFilterNullArray()
         throws Exception
  {
    Filter.createANDFilter((Filter[]) null);
  }



  /**
   * Tests the {@code createANDFilter} method with an empty list (i.e., an
   * "LDAP TRUE" filter).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterEmptyList()
         throws Exception
  {
    Filter f = Filter.createANDFilter(new ArrayList<Filter>(0));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a single-element list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterSingleElementList()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>(1);
    filterList.add(Filter.create("(foo=bar)"));

    Filter f = Filter.createANDFilter(filterList);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 1);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&(foo=bar))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a multi-element list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateANDFilterMultiElementList()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>(3);
    filterList.add(Filter.create("(a=b)"));
    filterList.add(Filter.create("(c=d)"));
    filterList.add(Filter.create("(e=f)"));

    Filter f = Filter.createANDFilter(filterList);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_AND);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 3);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(&(a=b)(c=d)(e=f))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createANDFilter} method with a null list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateANDFilterNullList()
         throws Exception
  {
    Filter.createANDFilter((ArrayList<Filter>) null);
  }



  /**
   * Tests the {@code createORFilter} method with an empty array (i.e., an
   * "LDAP FALSE" filter).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterEmptyArray()
         throws Exception
  {
    Filter f = Filter.createORFilter(new Filter[0]);

    String filterString = f.toString();
    assertEquals(filterString, "(|)");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterSingleElementArray()
         throws Exception
  {
    Filter[] filterElements =
    {
      Filter.create("(foo=bar)")
    };

    Filter f = Filter.createORFilter(filterElements);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 1);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(|(foo=bar))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterMultiElementArray()
         throws Exception
  {
    Filter[] filterElements =
    {
      Filter.create("(a=b)"),
      Filter.create("(c=d)"),
      Filter.create("(e=f)"),
    };

    Filter f = Filter.createORFilter(filterElements);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 3);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(|(a=b)(c=d)(e=f))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateORFilterNull()
         throws Exception
  {
    Filter.createORFilter((Filter[]) null);
  }



  /**
   * Tests the {@code createORFilter} method with an empty list (i.e., an
   * "LDAP FALSE" filter).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterEmptyList()
         throws Exception
  {
    Filter f = Filter.createORFilter(new ArrayList<Filter>(0));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(|)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a single-element list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterSingleElementList()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>(1);
    filterList.add(Filter.create("(foo=bar)"));

    Filter f = Filter.createORFilter(filterList);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 1);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(|(foo=bar))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a multi-element list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateORFilterMultiElementList()
         throws Exception
  {
    ArrayList<Filter> filterList = new ArrayList<Filter>(3);
    filterList.add(Filter.create("(a=b)"));
    filterList.add(Filter.create("(c=d)"));
    filterList.add(Filter.create("(e=f)"));

    Filter f = Filter.createORFilter(filterList);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 3);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(|(a=b)(c=d)(e=f))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createORFilter} method with a null list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateORFilterList()
         throws Exception
  {
    Filter.createORFilter((ArrayList<Filter>) null);
  }


  /**
   * Tests the {@code createNOTFilter} method with a valid filter component.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCreateNOTFilter()
         throws Exception
  {
    Filter f = Filter.createNOTFilter(Filter.create("(foo=bar)"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_NOT);

    assertNotNull(f.getNOTComponent());

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getAttributeName());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(!(foo=bar))");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createNOTFilter} method with a null filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateNOTFilterNull()
         throws Exception
  {
    Filter.createNOTFilter(null);
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a string
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterString()
         throws Exception
  {
    Filter f = Filter.createEqualityFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EQUALITY);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a string
   * value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterStringNullAttr()
         throws Exception
  {
    Filter.createEqualityFilter(null, "bar");
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a string
   * value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterStringNullValue()
         throws Exception
  {
    Filter.createEqualityFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a byte
   * array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createEqualityFilter("foo", "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EQUALITY);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a string
   * value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterByteArrayNullAttr()
         throws Exception
  {
    Filter.createEqualityFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a byte
   * array value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterByteArrayNullValue()
         throws Exception
  {
    Filter.createEqualityFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes an ASN.1
   * octet string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterOctetString()
         throws Exception
  {
    Filter f = Filter.createEqualityFilter("foo", new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EQUALITY);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes a string
   * value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterOctetStringNullAttr()
         throws Exception
  {
    Filter.createEqualityFilter(null, new ASN1OctetString("bar"));
  }



  /**
   * Tests the {@code createEqualityFilter} method variant that takes an ASN.1
   * octet string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterOctetStringNullValue()
         throws Exception
  {
    Filter.createEqualityFilter("foo", (ASN1OctetString) null);
  }



  /**
   * Tests the {@code createEqualityFilter} method to ensure that special
   * characters are properly escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterEscaping()
         throws Exception
  {
    final String valueString1 = "Jalape\u00f1o";
    final String valueString2 = "Latin Capital Letter OO \uA74E";
    final String valueString3 = "Deseret Capital Letter Long I \uD801\uDC00";
    final String valueString4 = "Smiley Face Emoji \uD83D\uDE00";
    final String valueString5 = "U.S. Flag Emoji \uD83C\uDDFA\uD83C\uDDF8";

    final Filter f = Filter.createORFilter(
         Filter.createEqualityFilter("cn", valueString1),
         Filter.createEqualityFilter("cn", valueString2),
         Filter.createEqualityFilter("cn", valueString3),
         Filter.createEqualityFilter("cn", valueString4),
         Filter.createEqualityFilter("cn", valueString5));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_OR);

    assertNull(f.getAttributeName());

    assertNull(f.getAssertionValue());

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 5);

    final String expectedFilterString =
         "(|(cn=Jalape\\c3\\b1o)" +
              "(cn=Latin Capital Letter OO \\ea\\9d\\8e)" +
              "(cn=Deseret Capital Letter Long I \\f0\\90\\90\\80)" +
              "(cn=Smiley Face Emoji \\f0\\9f\\98\\80)" +
              "(cn=U.S. Flag Emoji \\f0\\9f\\87\\ba\\f0\\9f\\87\\b8))";
    final String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    final Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    final ASN1Element filterElement = f.encode();
    final Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final String minimallyEncodedFilterString =
         "(|(cn=Jalape\u00f1o)" +
              "(cn=Latin Capital Letter OO \uA74E)" +
              "(cn=Deseret Capital Letter Long I \uD801\uDC00)" +
              "(cn=Smiley Face Emoji \uD83D\uDE00)" +
              "(cn=U.S. Flag Emoji \uD83C\uDDFA\uD83C\uDDF8))";
    final Filter decodedFromMinimallyEncodedFilterString =
         Filter.create(minimallyEncodedFilterString);
    assertEquals(decodedFromMinimallyEncodedFilterString, f);

    final String expectedNormalizedFilterString =
         "(|(cn=jalape\\c3\\b1o)" +
              "(cn=latin capital letter oo \\ea\\9d\\8f)" +
              "(cn=deseret capital letter long i \\f0\\90\\90\\a8)" +
              "(cn=smiley face emoji \\f0\\9f\\98\\80)" +
              "(cn=u.s. flag emoji \\f0\\9f\\87\\ba\\f0\\9f\\87\\b8))";
    assertEquals(f.toNormalizedString(), expectedNormalizedFilterString);
    assertEquals(decodedFromMinimallyEncodedFilterString.toNormalizedString(),
         expectedNormalizedFilterString);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing only a subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringSubInitialOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", "bar", null, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubInitialFilter} method with a string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubInitialFilterString()
         throws Exception
  {
    Filter f = Filter.createSubInitialFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringSingleSubAnyOnly()
         throws Exception
  {
    String[] subAny = { "bar" };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubAnyFilter} method variant with a single string
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubAnyFilterSingleStringValue()
         throws Exception
  {
    Filter f = Filter.createSubAnyFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing only multiple subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringMultipleSubAnyOnly()
         throws Exception
  {
    String[] subAny = { "bar", "baz", "bat" };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*baz*bat*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubAnyFilter} method variant that takes multiple
   * string values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubAnyFilterMultipleStringValues()
         throws Exception
  {
    Filter f = Filter.createSubAnyFilter("foo", "bar", "baz", "bat");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*baz*bat*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing only a subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringSubFinalOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", null, null, "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bar");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubFinalFilter} method with a string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubFinalFilterString()
         throws Exception
  {
    Filter f = Filter.createSubFinalFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bar");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing all components, with only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringAllSingleSubAny()
         throws Exception
  {
    String[] subAny = { "baz" };

    Filter f = Filter.createSubstringFilter("foo", "bar", subAny, "bat");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bat");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bat");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bat");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*baz*bat)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing all components, with multiple subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringAllMultipleSubAny()
         throws Exception
  {
    String[] subAny = { "bar", "baz", "bat" };

    Filter f = Filter.createSubstringFilter("foo", "a", subAny, "c");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "a");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "a");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "a");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "c");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "c");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "c");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=a*bar*baz*bat*c)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullAttr()
         throws Exception
  {
    Filter.createSubstringFilter(null, "bar", null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing null arguments for all substring components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullSubstring()
         throws Exception
  {
    Filter.createSubstringFilter("null", (String) null, null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes string
   * arguments by providing null arguments for the subInitial and subFinal
   * components and an empty array for the subAny components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullSubInitialAndFinalEmptyAny()
         throws Exception
  {
    Filter.createSubstringFilter("null", null, new String[0], null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing only a subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArraySubInitialOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", "bar".getBytes("UTF-8"),
                                            null, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubInitialFilter} method variant that takes a byte
   * array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubInitialFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createSubInitialFilter("foo", "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArraySingleSubAnyOnly()
         throws Exception
  {
    byte[][] subAny = { "bar".getBytes("UTF-8") };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubAnyFilter} method with a single byte array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubAnyFilterSingleByteArrayValue()
         throws Exception
  {
    Filter f = Filter.createSubAnyFilter("foo", "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing only multiple subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArrayMultipleSubAnyOnly()
         throws Exception
  {
    byte[][] subAny = { "bar".getBytes("UTF-8"), "baz".getBytes("UTF-8"),
                        "bat".getBytes("UTF-8") };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*baz*bat*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubAnyFilter} method with multiple byte array
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubAnyFilterMultipleByteArrayValues()
         throws Exception
  {
    Filter f = Filter.createSubAnyFilter("foo", "bar".getBytes("UTF-8"),
         "baz".getBytes("UTF-8"), "bat".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*baz*bat*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing only a subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArraySubFinalOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", null, null,
                                            "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bar");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubFinalFilter} method variant that takes a byte
   * array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubFinalFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createSubFinalFilter("foo", "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bar");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing all components, with only a single subAny
   * element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArrayAllSingleSubAny()
         throws Exception
  {
    byte[][] subAny = { "baz".getBytes("UTF-8") };

    Filter f = Filter.createSubstringFilter("foo", "bar".getBytes("UTF-8"),
                                            subAny, "bat".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bat");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bat");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bat");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*baz*bat)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing all components, with multiple subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterByteArrayAllMultipleSubAny()
         throws Exception
  {
    byte[][] subAny = { "bar".getBytes("UTF-8"), "baz".getBytes("UTF-8"),
                        "bat".getBytes("UTF-8") };

    Filter f = Filter.createSubstringFilter("foo", "a".getBytes("UTF-8"),
                                            subAny, "c".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "a");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "a");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "a");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "c");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "c");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "c");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=a*bar*baz*bat*c)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterByteArrayNullAttr()
         throws Exception
  {
    Filter.createSubstringFilter(null, "bar".getBytes("UTF-8"), null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing null arguments for all substring components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterByteArrayNullSubstring()
         throws Exception
  {
    Filter.createSubstringFilter("null", (byte[]) null, null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes byte
   * array arguments by providing null arguments for the subInitial and subFinal
   * components and an empty array for the subAny components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterByteArrayNullSubInitialAndFinalEmptyAny()
         throws Exception
  {
    Filter.createSubstringFilter("null", null, new byte[0][], null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing only a subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringSubInitialOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", new ASN1OctetString("bar"),
                                            null, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringSingleSubAnyOnly()
         throws Exception
  {
    ASN1OctetString[] subAny = { new ASN1OctetString("bar") };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing only multiple subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringMultipleSubAnyOnly()
         throws Exception
  {
    ASN1OctetString[] subAny =
    {
      new ASN1OctetString("bar"),
      new ASN1OctetString("baz"),
      new ASN1OctetString("bat")
    };

    Filter f = Filter.createSubstringFilter("foo", null, subAny, null);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar*baz*bat*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing only a subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringSubFinalOnly()
         throws Exception
  {
    Filter f = Filter.createSubstringFilter("foo", null, null,
                                            new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bar");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing all components, with only a single
   * subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringAllSingleSubAny()
         throws Exception
  {
    ASN1OctetString[] subAny = { new ASN1OctetString("baz") };

    Filter f = Filter.createSubstringFilter("foo", new ASN1OctetString("bar"),
                                            subAny, new ASN1OctetString("bat"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "bar");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "bat");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "bat");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bat");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 1);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 1);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=bar*baz*bat)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing all components, with multiple subAny
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterOctetStringAllMultipleSubAny()
         throws Exception
  {
    ASN1OctetString[] subAny =
    {
      new ASN1OctetString("bar"),
      new ASN1OctetString("baz"),
      new ASN1OctetString("bat")
    };

    Filter f = Filter.createSubstringFilter("foo", new ASN1OctetString("a"),
                                            subAny, new ASN1OctetString("c"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), "a");

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), "a");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "a");

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), "c");

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), "c");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "c");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 3);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 3);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 3);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=a*bar*baz*bat*c)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterOctetStringNullAttr()
         throws Exception
  {
    Filter.createSubstringFilter(null, new ASN1OctetString("bar"), null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing null arguments for all substring
   * components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterOctetStringNullSubstring()
         throws Exception
  {
    Filter.createSubstringFilter("null", (ASN1OctetString) null, null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method variant that takes ASN.1
   * octet string arguments by providing null arguments for the subInitial and
   * subFinal components and an empty array for the subAny components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void
       testCreateSubstringFilterOctetStringNullSubInitialAndFinalEmptyAny()
       throws Exception
  {
    Filter.createSubstringFilter("null", null, new ASN1OctetString[0], null);
  }



  /**
   * Tests the {@code createSubstringFilter} method to ensure that special
   * characters are properly escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterEscaping()
         throws Exception
  {
    String subInitial = "Jos\u00e9";
    String subFinal   = "Jalape\u00f1o";
    String[] subAny =
    {
      "(",
      "on",
      "*",
      "a",
      "\\",
      "stick",
      ")"
    };

    Filter f = Filter.createSubstringFilter("foo", subInitial, subAny,
                                            subFinal);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_SUBSTRING);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getSubInitialString());
    assertEquals(f.getSubInitialString(), subInitial);

    assertNotNull(f.getSubInitialBytes());
    assertEquals(toUTF8String(f.getSubInitialBytes()), subInitial);

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), subInitial);

    assertNotNull(f.getSubFinalString());
    assertEquals(f.getSubFinalString(), subFinal);

    assertNotNull(f.getSubFinalBytes());
    assertEquals(toUTF8String(f.getSubFinalBytes()), subFinal);

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), subFinal);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 7);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 7);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 7);

    String expectedFilterString =
      "(foo=Jos\\c3\\a9*\\28*on*\\2a*a*\\5c*stick*\\29*Jalape\\c3\\b1o)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterString()
         throws Exception
  {
    Filter f = Filter.createGreaterOrEqualFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_GREATER_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo>=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterStringNullAttr()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter(null, "bar");
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterStringNullValue()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * byte array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createGreaterOrEqualFilter("foo",
                                                 "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_GREATER_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo>=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterByteArrayNullAttr()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * byte array value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterByteArrayNullValue()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes an
   * ASN.1 octet string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterOctetString()
         throws Exception
  {
    Filter f = Filter.createGreaterOrEqualFilter("foo",
                                                 new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_GREATER_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo>=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterOctetStringNullAttr()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter(null, new ASN1OctetString("bar"));
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method variant that takes an
   * ASN.1 octet string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterOctetStringNullValue()
         throws Exception
  {
    Filter.createGreaterOrEqualFilter("foo", (ASN1OctetString) null);
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method to ensure that special
   * characters are properly escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterEscaping()
         throws Exception
  {
    String valueString = "\\* Jos\u00e9 Jalape\u00f1o (on a stick) \\*";
    Filter f = Filter.createGreaterOrEqualFilter("foo", valueString);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_GREATER_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), valueString);

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), valueString);

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), valueString);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String expectedFilterString =
      "(foo>=\\5c\\2a Jos\\c3\\a9 Jalape\\c3\\b1o \\28on a stick\\29 \\5c\\2a)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    assertEquals(
         "(foo>=" + Filter.encodeValue(valueString) + ")",
         expectedFilterString);
    assertEquals(
         "(foo>=" + Filter.encodeValue(valueString.getBytes("UTF-8")) + ")",
         expectedFilterString);

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterString()
         throws Exception
  {
    Filter f = Filter.createLessOrEqualFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_LESS_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo<=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterStringNullAttr()
         throws Exception
  {
    Filter.createLessOrEqualFilter(null, "bar");
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterStringNullValue()
         throws Exception
  {
    Filter.createLessOrEqualFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * byte array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createLessOrEqualFilter("foo", "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_LESS_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo<=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterByteArrayNullAttr()
         throws Exception
  {
    Filter.createLessOrEqualFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * byte array value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterByteArrayNullValue()
         throws Exception
  {
    Filter.createLessOrEqualFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes an
   * ASN.1 octet string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterOctetString()
         throws Exception
  {
    Filter f = Filter.createLessOrEqualFilter("foo",
                                              new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_LESS_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo<=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterOctetStringNullAttr()
         throws Exception
  {
    Filter.createLessOrEqualFilter(null, new ASN1OctetString("bar"));
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method variant that takes an
   * ASN.1 octet string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterOctetStringNullValue()
         throws Exception
  {
    Filter.createLessOrEqualFilter("foo", (ASN1OctetString) null);
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method to ensure that special
   * characters are properly escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterEscaping()
         throws Exception
  {
    String valueString = "\\* Jos\u00e9 Jalape\u00f1o (on a stick) \\*";
    Filter f = Filter.createLessOrEqualFilter("foo", valueString);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_LESS_OR_EQUAL);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), valueString);

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), valueString);

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), valueString);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String expectedFilterString =
      "(foo<=\\5c\\2a Jos\\c3\\a9 Jalape\\c3\\b1o \\28on a stick\\29 \\5c\\2a)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    assertEquals(
         "(foo<=" + Filter.encodeValue(valueString) + ")",
         expectedFilterString);
    assertEquals(
         "(foo<=" + Filter.encodeValue(valueString.getBytes("UTF-8")) + ")",
         expectedFilterString);

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createPresenceFilter} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePresenceFilter()
         throws Exception
  {
    Filter f = Filter.createPresenceFilter("foo");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_PRESENCE);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo=*)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createPresenceFilter} method with a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreatePresenceFilterNullAttr()
         throws Exception
  {
    Filter.createPresenceFilter(null);
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateMatchFilterString()
         throws Exception
  {
    Filter f = Filter.createApproximateMatchFilter("foo", "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_APPROXIMATE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo~=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterStringNullAttr()
         throws Exception
  {
    Filter.createApproximateMatchFilter(null, "bar");
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterStringNullValue()
         throws Exception
  {
    Filter.createApproximateMatchFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * byte array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateMatchFilterByteArray()
         throws Exception
  {
    Filter f = Filter.createApproximateMatchFilter("foo",
                                                   "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_APPROXIMATE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo~=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterByteArrayNullAttr()
         throws Exception
  {
    Filter.createApproximateMatchFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * byte array value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterByteArrayNullValue()
         throws Exception
  {
    Filter.createApproximateMatchFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes an
   * ASN.1 octet string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateMatchFilterOctetString()
         throws Exception
  {
    Filter f = Filter.createApproximateMatchFilter("foo",
                                                   new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_APPROXIMATE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo~=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes a
   * string value by providing a null attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterOctetStringNullAttr()
         throws Exception
  {
    Filter.createApproximateMatchFilter(null, new ASN1OctetString("bar"));
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method variant that takes an
   * ASN.1 octet string value by providing a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateMatchFilterOctetStringNullValue()
         throws Exception
  {
    Filter.createApproximateMatchFilter("foo", (ASN1OctetString) null);
  }



  /**
   * Tests the {@code createApproximateMatchFilter} method to ensure that
   * special characters are properly escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateMatchFilterEscaping()
         throws Exception
  {
    String valueString = "\\* Jos\u00e9 Jalape\u00f1o (on a stick) \\*";
    Filter f = Filter.createApproximateMatchFilter("foo", valueString);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_APPROXIMATE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), valueString);

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), valueString);

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), valueString);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String expectedFilterString =
      "(foo~=\\5c\\2a Jos\\c3\\a9 Jalape\\c3\\b1o \\28on a stick\\29 \\5c\\2a)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    assertEquals(
         "(foo~=" + Filter.encodeValue(valueString) + ")",
         expectedFilterString);
    assertEquals(
         "(foo~=" + Filter.encodeValue(valueString.getBytes("UTF-8")) + ")",
         expectedFilterString);

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with an attribute name but no matching rule ID and
   * no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringAttr()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, false, "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with an attribute name but no matching rule ID and
   * with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringAttrDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, true, "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with a matching rule ID but no attribute name and
   * no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", false, "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with a matching rule ID but no attribute name and
   * with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", true, "bar");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:dn:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with an attribute name, matching rule ID, and no
   * dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringAttrRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", false, "baz");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with an attribute name, matching rule ID, and
   * dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringAttrRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", true, "baz");

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with no assertion value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterStringNoValue()
  {
    Filter.createExtensibleMatchFilter("foo", null, false, (String) null);
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * string assertion value with neither an attribute name nor a matching rule
   * ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterStringNoAttrOrRuleID()
  {
    Filter.createExtensibleMatchFilter(null, null, false, "bar");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with an attribute name but no matching rule ID
   * and no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayAttr()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, false,
                                                  "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with an attribute name but no matching rule ID
   * and with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayAttrDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, true,
                                                  "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with a matching rule ID but no attribute name
   * and no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", false,
                                                  "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with a matching rule ID but no attribute name
   * and with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", true,
                                                  "bar".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:dn:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with an attribute name, matching rule ID, and no
   * dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayAttrRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", false,
                                                  "baz".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with an attribute name, matching rule ID, and
   * dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterByteArrayAttrRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", true,
                                                  "baz".getBytes("UTF-8"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with no assertion value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterByteArrayNoValue()
  {
    Filter.createExtensibleMatchFilter("foo", null, false, (byte[]) null);
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes a
   * byte array assertion value with neither an attribute name nor a matching
   * rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterByteArrayNoAttrOrRuleID()
         throws Exception
  {
    Filter.createExtensibleMatchFilter(null, null, false,
                                       "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with an attribute name but no matching
   * rule ID and no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringAttr()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, false,
                                                  new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with an attribute name but no matching
   * rule ID and with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringAttrDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", null, true,
                                                  new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string string assertion value with a matching rule ID but no
   * attribute name and no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", false,
                                                  new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with a matching rule ID but no attribute
   * name and with the dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", true,
                                                  new ASN1OctetString("bar"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(:dn:foo:=bar)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with an attribute name, matching rule
   * ID, and no dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringAttrRuleID()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", false,
                                                  new ASN1OctetString("baz"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertFalse(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with an attribute name, matching rule
   * ID, and dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterOctetStringAttrRuleIDDN()
         throws Exception
  {
    Filter f = Filter.createExtensibleMatchFilter("foo", "bar", true,
                                                  new ASN1OctetString("baz"));

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String filterString = f.toString();
    assertEquals(filterString, "(foo:dn:bar:=baz)");

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with no assertion value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterOctetStringNoValue()
  {
    Filter.createExtensibleMatchFilter("foo", null, false,
                                       (ASN1OctetString) null);
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method variant that takes an
   * ASN.1 octet string assertion value with neither an attribute name nor a
   * matching rule ID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterOctetStringNoAttrOrRuleID()
  {
    Filter.createExtensibleMatchFilter(null, null, false,
                                       new ASN1OctetString("bar"));
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method to ensure that special
   * characters are properly escaped when an attribute name is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterEscapingAttr()
         throws Exception
  {
    String valueString = "\\* Jos\u00e9 Jalape\u00f1o (on a stick) \\*";
    Filter f = Filter.createExtensibleMatchFilter("foo", null, true,
                                                  valueString);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getAttributeName());
    assertEquals(f.getAttributeName(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), valueString);

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), valueString);

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), valueString);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());
    assertNull(f.getMatchingRuleID());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String expectedFilterString =
         "(foo:dn:=\\5c\\2a Jos\\c3\\a9 Jalape\\c3\\b1o \\28on a stick\\29 " +
         "\\5c\\2a)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method to ensure that special
   * characters are properly escaped when a matching rule ID is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterEscapingRuleID()
         throws Exception
  {
    String valueString = "\\* Jos\u00e9 Jalape\u00f1o (on a stick) \\*";
    Filter f = Filter.createExtensibleMatchFilter(null, "foo", true,
                                                  valueString);

    assertEquals(f.getFilterType(), Filter.FILTER_TYPE_EXTENSIBLE_MATCH);

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), valueString);

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), valueString);

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), valueString);

    assertNotNull(f.getComponents());
    assertEquals(f.getComponents().length, 0);

    assertNull(f.getNOTComponent());
    assertNull(f.getAttributeName());
    assertNull(f.getSubInitialString());
    assertNull(f.getSubInitialBytes());
    assertNull(f.getRawSubInitialValue());
    assertNull(f.getSubFinalString());
    assertNull(f.getSubFinalBytes());
    assertNull(f.getRawSubFinalValue());

    assertTrue(f.getDNAttributes());

    assertNotNull(f.getSubAnyStrings());
    assertEquals(f.getSubAnyStrings().length, 0);

    assertNotNull(f.getSubAnyBytes());
    assertEquals(f.getSubAnyBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    String expectedFilterString =
         "(:dn:foo:=\\5c\\2a Jos\\c3\\a9 Jalape\\c3\\b1o \\28on a stick\\29 " +
         "\\5c\\2a)";
    String filterString = f.toString();
    assertEquals(filterString, expectedFilterString);

    Filter decodedFromString = Filter.create(filterString);
    assertEquals(decodedFromString.toString(), filterString);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.toString(), filterString);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code create} method which takes a string representation using
   * a valid filter string.
   *
   * @param  filterString  The string representation of the filter to create.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidFilterStrings")
  public void testCreateValid(String filterString)
         throws Exception
  {
    Filter f = Filter.create(filterString);

    String filterStr = f.toString();
    Filter decodedFromString = Filter.create(filterStr);
    assertEquals(decodedFromString.hashCode(), f.hashCode());
    assertEquals(decodedFromString, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromString.toNormalizedString());

    ASN1Element filterElement = f.encode();
    Filter decodedFromElement = Filter.decode(filterElement);
    assertEquals(decodedFromElement.hashCode(), f.hashCode());
    assertEquals(decodedFromElement, f);
    assertEquals(f.toNormalizedString(),
                 decodedFromElement.toNormalizedString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    f.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    f.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code create} method which takes a string representation using
   * an invalid filter string.
   *
   * @param  filterString  The string representation of the filter to create.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidFilterStrings",
        expectedExceptions = { LDAPException.class })
  public void testCreateInvalid(String filterString)
         throws Exception
  {
    Filter.create(filterString);
  }



  /**
   * Tests the behavior of the {@code create} method with a filter string that
   * is nested too deeply.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDeeplyNestedFilter()
         throws Exception
  {
    String filterStr = "(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&" +
         "(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&" +
         "(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&" +
         "(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&(&((&(&(&(&(&(&(&(&(a=b)))))" +
         "))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))" +
         ")))))))))))))))))))))))))))))))))))))))))))))))))))";
    Filter.create(filterStr);
  }



  /**
   * Tests the {@code equals} method with a null object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    Filter f = Filter.create("(a=b)");
    assertFalse(f.equals(null));
  }



  /**
   * Tests the {@code equals} method with an identity comparison.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    Filter f = Filter.create("(a=b)");
    assertTrue(f.equals(f));
  }



  /**
   * Tests the {@code equals} method with an object that isn't a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotFilter()
         throws Exception
  {
    Filter f = Filter.create("(a=b)");
    assertFalse(f.equals("not a filter"));
  }



  /**
   * Tests the {@code equals} method with a filter of a different type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentFilterType()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b)");
    Filter f2 = Filter.create("(a>=b)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with AND filters with different numbers of
   * components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsANDDifferentComponentCount()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(a=b)(c=d)(e=f))");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with AND filters with the same number, but
   * non-matching, components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsANDDifferentComponents()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(a=b)(e=f))");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with AND filters with the same components
   * but in a different order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsANDDifferentComponentOrder()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(c=d)(a=b))");

    assertTrue(f1.equals(f2));
    assertTrue(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an equality filter with different
   * attribute names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEqualityDifferentAttrs()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b)");
    Filter f2 = Filter.create("(c=b)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an equality filter with the same
   * attribute names in different cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEqualityDifferentAttrCases()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b)");
    Filter f2 = Filter.create("(A=b)");

    assertTrue(f1.equals(f2));
    assertTrue(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter with different
   * attribute names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringDifferentAttrs()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*)");
    Filter f2 = Filter.create("(c=b*)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter with different
   * subAny lengths.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringDifferentSubAnyCounts()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=b*c*e*d)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter missing subInitial
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringMissingSubInitial()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=*c*d)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter with different
   * subInitial elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringDifferentSubInitial()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=e*c*d)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter missing subInitial
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringMissingSubFinal()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=b*c*)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter with different
   * subFinal elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringDifferentSubFinal()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=b*c*e)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an substring filter with different
   * subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSubstringDifferentSubAny()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=b*e*d)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an extensible match filter with
   * different attribute names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtensibleMatchDifferentAttrNames()
         throws Exception
  {
    Filter f1 = Filter.create("(a:=b)");
    Filter f2 = Filter.create("(c:=b)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an extensible match filter with
   * a missing attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtensibleMatchMissingAttrName()
         throws Exception
  {
    Filter f1 = Filter.create("(:a:=b)");
    Filter f2 = Filter.create("(a:=b)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an extensible match filter with
   * different matching rule IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtensibleMatchDifferentRuleIDs()
         throws Exception
  {
    Filter f1 = Filter.create("(a:dn:b:=c)");
    Filter f2 = Filter.create("(c:dn:d:=c)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an extensible match filter with
   * a missing attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtensibleMatchMissingRuleID()
         throws Exception
  {
    Filter f1 = Filter.create("(a:b:=c)");
    Filter f2 = Filter.create("(a:=c)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code equals} method with an extensible match filter with
   * different dnAttributes flags.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtensibleMatchDifferentDNAttrs()
         throws Exception
  {
    Filter f1 = Filter.create("(a:=b)");
    Filter f2 = Filter.create("(a:dn:=b)");

    assertFalse(f1.equals(f2));
    assertFalse(f2.equals(f1));
  }



  /**
   * Tests the {@code matchesEntry} method.
   *
   * @param  filter    The filter to compare against the target entry.
   * @param  expected  The expected result from the comparison.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="acceptableFilters")
  public void testMatchesEntryAcceptable(String filter, Boolean expected)
         throws Exception
  {
    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn: User, Test",
         "cn: User",
         "description: This is a test");

    final Filter parsedFilter = Filter.create(filter);

    try
    {
      assertEquals(parsedFilter.matchesEntry(e),
           expected.booleanValue());
      assertEquals(Filter.createNOTFilter(parsedFilter).matchesEntry(e),
           (! expected.booleanValue()));
      assertEquals(Filter.createNOTFilter(parsedFilter).matchesEntry(e, schema),
           (! expected.booleanValue()));
    }
    catch (final LDAPException le)
    {
      // This should only happen for extensible matching filters.
      assertEquals(parsedFilter.getFilterType(),
           Filter.FILTER_TYPE_EXTENSIBLE_MATCH);
    }

    assertNotNull(parsedFilter.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    parsedFilter.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    parsedFilter.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code matchesEntry} method to ensure that it doesn't throw an
   * exception with any valid filter, except for filter types that are not
   * supported by the current implementation.
   *
   * @param  filter  The filter to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidFilterStrings")
  public void testMatchesEntryValid(String filter)
         throws Exception
  {
    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "cn: User, Test",
         "cn: User",
         "description: This is a test");

    Filter f = Filter.create(filter);
    if ((f.getFilterType() == Filter.FILTER_TYPE_APPROXIMATE_MATCH) ||
        (f.getFilterType() == Filter.FILTER_TYPE_EXTENSIBLE_MATCH))
    {
      try
      {
        f.matchesEntry(e, schema);
        fail("Expected an exception when trying to compare filter " + filter +
             " against an entry.");
      }
      catch (LDAPException le)
      {
        // This was expected.
      }
    }
    else
    {
      f.matchesEntry(e, schema);
    }
  }



  /**
   * Tests the {@code readFrom} and {@code writeTo} methods.
   *
   * @param  filter  The string representation of the filter to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidFilterStrings")
  public void testReadAndWrite(final String filter)
         throws Exception
  {
    Filter provided = Filter.create(filter);

    ASN1Buffer b = new ASN1Buffer();
    provided.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    Filter decoded = Filter.readFrom(reader);
    assertEquals(decoded, provided);
  }



  /**
   * Retrieves a set of valid filter strings.
   *
   * @return  A set of valid filter strings.
   */
  @DataProvider(name = "testValidFilterStrings")
  public Object[][] getTestValidFilterStrings()
  {
    return new Object[][]
    {
      new Object[] { "(foo=)" },
      new Object[] { "(foo>=)" },
      new Object[] { "(foo<=)" },
      new Object[] { "(foo~=)" },
      new Object[] { "(foo:=)" },
      new Object[] { "(foo:dn:=)" },
      new Object[] { "(:foo:=)" },
      new Object[] { "(:dn:foo:=)" },
      new Object[] { "(foo=*)" },
      new Object[] { "(foo=a)" },
      new Object[] { "(foo>=a)" },
      new Object[] { "(foo<=a)" },
      new Object[] { "(foo~=a)" },
      new Object[] { "(foo:=a)" },
      new Object[] { "(foo:dn:=a)" },
      new Object[] { "(:foo:=a)" },
      new Object[] { "(:dn:foo:=a)" },
      new Object[] { "(foo=bar)" },
      new Object[] { "(foo>=bar)" },
      new Object[] { "(foo<=bar)" },
      new Object[] { "(foo~=bar)" },
      new Object[] { "(foo=bar*)" },
      new Object[] { "(foo=*bar*)" },
      new Object[] { "(foo=*bar)" },
      new Object[] { "(foo=bar*baz*bat)" },
      new Object[] { "(foo:=bar)" },
      new Object[] { "(foo:dn:=bar)" },
      new Object[] { "(:dn:foo:=bar)" },
      new Object[] { "(foo:dn:bar:=baz)" },
      new Object[] { "(:foo:=bar)" },
      new Object[] { "(&)" },
      new Object[] { "(&(a=b))" },
      new Object[] { "(&(a=b)(c=d))" },
      new Object[] { "(&(a=b)(c=d)(e=f)(g=h)(i=j)(k=l)(m=n)(o=p)(q=r)(s=t)" +
                       "(u=v)(w=x)(y=z))" },
      new Object[] { "(&(&(&(&(&(&(&(&(&(&(&(a=b)(c=d))(e=f))(g=h))(i=j))" +
                       "(k=l)(m=n))(o=p))(q=r))(s=t))(u=v))(w=x))(y=z))" },
      new Object[] { "(|)" },
      new Object[] { "(|(a=b))" },
      new Object[] { "(|(a=b)(c=d))" },
      new Object[] { "(|(a=b)(c=d)(e=f)(g=h)(i=j)(k=l)(m=n)(o=p)(q=r)(s=t)" +
                       "(u=v)(w=x)(y=z))" },
      new Object[] { "(|(|(|(|(|(|(|(|(|(|(|(a=b)(c=d))(e=f))(g=h))(i=j))" +
                       "(k=l)(m=n))(o=p))(q=r))(s=t))(u=v))(w=x))(y=z))" },
      new Object[] { "(|(&(|(&(|(&(|(&(|(&(|(a=b)(c=d))(e=f))(g=h))(i=j))" +
                       "(k=l)(m=n))(o=p))(q=r))(s=t))(u=v))(w=x))(y=z))" },
      new Object[] { "(foo=\\00\\11\\22\\33\\44\\55\\66\\77)" },
      new Object[] { "(foo=\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f)" },
      new Object[] { "(!(foo=bar))" },

      // These are technically invalid but are still common practice so we'll
      // allow them.
      new Object[] { "foo=" },
      new Object[] { "foo=*" },
      new Object[] { "foo=a" },
      new Object[] { "foo=bar" },
      new Object[] { "foo>=bar" },
      new Object[] { "foo<=bar" },
      new Object[] { "foo~=bar" },
      new Object[] { "foo:=bar" },
      new Object[] { "foo:dn:=bar" },
      new Object[] { ":dn:foo:=bar" },
      new Object[] { "foo:dn:bar:=baz" },
    };
  }


  /**
   * Retrieves a set of invalid filter strings.
   *
   * @return  A set of invalid filter strings.
   */
  @DataProvider(name = "testInvalidFilterStrings")
  public Object[][] getTestInvalidFilterStrings()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { "(" },
      new Object[] { ")" },
      new Object[] { "()" },
      new Object[] { "(foo)" },
      new Object[] { "&foo=bar" },
      new Object[] { "(=bar)" },
      new Object[] { "(>=bar)" },
      new Object[] { "(<=bar)" },
      new Object[] { "(~=bar)" },
      new Object[] { "(:=bar)" },
      new Object[] { "(:dn:=bar)" },
      new Object[] { "(foo=bar" },
      new Object[] { "((foo=bar))" },
      new Object[] { "((a=b)c" },
      new Object[] { "(a=b)(c=d)" },
      new Object[] { "(::=bar)" },
      new Object[] { "(:dn::=bar)" },
      new Object[] { "(:bogus:foo:=bar)" },
      new Object[] { "(:dn:a:b:=bar)" },
      new Object[] { "(:dn:foo:a=bar)" },
      new Object[] { "(:foo:a=bar)" },
      new Object[] { "(foo=ba(r)" },
      new Object[] { "(foo=ba)r)" },
      new Object[] { "(foo:=ba(r)" },
      new Object[] { "(foo:=ba)r)" },
      new Object[] { "(foo:dn:=ba(r)" },
      new Object[] { "(foo:dn:=ba)r)" },
      new Object[] { "(:dn:foo:=ba(r)" },
      new Object[] { "(:dn:foo:=ba)r)" },
      new Object[] { "(foo=**bar)" },
      new Object[] { "(foo=bar**)" },
      new Object[] { "(foo=bar**baz)" },
      new Object[] { "(foo=*bar**baz**bat*)" },
      new Object[] { "(foo>)" },
      new Object[] { "(foo<)" },
      new Object[] { "(foo~)" },
      new Object[] { "(foo:)" },
      new Object[] { "(foo>bar)" },
      new Object[] { "(foo<bar)" },
      new Object[] { "(foo~bar)" },
      new Object[] { "(foo:bar)" },
      new Object[] { "(foo:dn=bar)" },
      new Object[] { "(:dn:bar=baz)" },
      new Object[] { "(foo:dn:bar=baz)" },
      new Object[] { "(foo::=bar)" },
      new Object[] { "(:dn::=bar)" },
      new Object[] { "(foo:dn::=bar)" },
      new Object[] { "(foo=\\xx)" },
      new Object[] { "(foo=\\ax)" },
      new Object[] { "(foo=\\a)" },
      new Object[] { "(foo=a\\b)" },
      new Object[] { "(foo=\\)" },
      new Object[] { "(foo>=\\xx)" },
      new Object[] { "(foo>=\\ax)" },
      new Object[] { "(foo>=\\a)" },
      new Object[] { "(foo>=a\\b)" },
      new Object[] { "(foo>=\\)" },
      new Object[] { "(foo=))" },
      new Object[] { "(foo=()" },
      new Object[] { "(foo>=*)" },
      new Object[] { "(foo<=*)" },
      new Object[] { "(foo~=*)" },
      new Object[] { "(foo:=*)" },
      new Object[] { "(foo>=*)" },
      new Object[] { "(foo>=()" },
      new Object[] { "(foo<=()" },
      new Object[] { "(foo~=()" },
      new Object[] { "(foo:=()" },
      new Object[] { "(foo>=()" },
      new Object[] { "(foo>=))" },
      new Object[] { "(foo<=))" },
      new Object[] { "(foo~=))" },
      new Object[] { "(foo:=))" },
      new Object[] { "(foo>=))" },
      new Object[] { "(foo>=bar*baz)" },
      new Object[] { "(&(a=b)(c=d)" },
      new Object[] { "(&(a=b)((c=d))" },
      new Object[] { "(&(a=b))(c=d))" },
    };
  }



  /**
   * Provides a set of valid filters and expected results that can be used to
   * test matching against an entry.
   *
   * @return  A set of valid filters and expected results that can be used to
   *          test matching against an entry.
   */
  @DataProvider(name="acceptableFilters")
  public Object[][] getAcceptableFilters()
  {
    return new Object[][]
    {
      new Object[]
      {
        "(objectClass=*)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(missing=*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(objectClass=top)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(objectClass=missing)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(missing=Test*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName=Test*)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=Testy*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(missing=*Test*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName=*Test*)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=*Testy*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(missing=*Test)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName=*Test)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=*Testy)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName=*T*e*s*t)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=T*t)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=T*st)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName=Te*es*st)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName=*T*q*t)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(missing>=Test)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName>=Test)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName>=aTest)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName>=zTest)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(missing<=Test)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName<=Test)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(givenName<=aTest)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(givenName<=zTest)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(&)",
        Boolean.TRUE
      },

      new Object[]
      {
        "(&(objectClass=top))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(&(objectClass=person)(givenName=Test))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(&(objectClass=missing)(givenName=Test))",
        Boolean.FALSE
      },

      new Object[]
      {
        "(&(objectClass=top)(missing=Test))",
        Boolean.FALSE
      },

      new Object[]
      {
        "(|)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(|(objectClass=top))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(|(objectClass=person)(givenName=Test))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(|(objectClass=missing)(givenName=Test))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(|(objectClass=person)(missing=test))",
        Boolean.TRUE
      },

      new Object[]
      {
        "(userPassword=sensitive)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(userPassword=sensitive*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(userPassword=*sensitive*)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(userPassword=*sensitive)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(userPassword=sensitive*sensitive*sensitive*sensitive)",
        Boolean.FALSE
      },

      new Object[]
      {
        "(userPassword:=sensitive)",
        Boolean.FALSE
      },

      new Object[]
      {
        Filter.createSubstringFilter("description",
             "jalape\\c3\\b1o",
             new String[] { "jalape\\c3\\b1o" },
             "jalape\\c3\\b1o").toString(),
        Boolean.FALSE
      }
    };
  }



  /**
   * Tests the behavior of the matchesEntry method when the provided filter uses
   * the jsonObjectFilterExtensibleMatch matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchesEntryJSONObjectExtensibleMatch()
         throws Exception
  {
    final Entry entry = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: ubidPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "ubidEmailJSON: not-a-valid-json-object",
         "ubidEmailJSON: " +
              new JSONObject(
                   new JSONField("type", "personal"),
                   new JSONField("value", "test.user@example.com"),
                   new JSONField("primary", true)).toSingleLineString());

    JSONObjectFilter jsonObjectFilter = new EqualsJSONObjectFilter(
         "value", "test.user@example.com");
    Filter filter = jsonObjectFilter.toLDAPFilter("ubidEmailJSON");
    assertTrue(filter.matchesEntry(entry));

    jsonObjectFilter = new EqualsJSONObjectFilter(
         "value", "different.user@example.com");
    filter = jsonObjectFilter.toLDAPFilter("ubidEmailJSON");
    assertFalse(filter.matchesEntry(entry));

    filter = jsonObjectFilter.toLDAPFilter("nonexistentAttribute");
    assertFalse(filter.matchesEntry(entry));

    try
    {
      filter = Filter.createExtensibleMatchFilter("ubidEmailJSON",
           "1.3.6.1.4.1.30221.2.4.13", false, "not-a-valid-json-object");
      filter.matchesEntry(entry);
      fail("Expected an exception when trying to use a JSON object filter " +
           "whose assertion value is not a valid JSON object");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.INAPPROPRIATE_MATCHING);
    }

    try
    {
      filter = Filter.createExtensibleMatchFilter("ubidEmailJSON",
           "1.3.6.1.4.1.30221.2.4.13", false, "{}");
      filter.matchesEntry(entry);
      fail("Expected an exception when trying to use a JSON object filter " +
           "whose assertion value is a valid JSON object but not a valid " +
           "JSON object filter");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.INAPPROPRIATE_MATCHING);
    }
  }



  /**
   * Tests the behavior of the simplifyFilter method, with and without filter
   * reordering.
   *
   * @param  original                     The string representation of the
   *                                      original filter to be simplified.
   * @param  simplifiedWithoutReordering  The string representation of the
   *                                      expected simplified filter without
   *                                      reordering.
   * @param  simplifiedWithReordering     The string representation of the
   *                                      expected simplified filter with
   *                                      reordering.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="simplifyFilterTestData")
  public void testSimplifyFilter(final String original,
                                 final String simplifiedWithoutReordering,
                                 final String simplifiedWithReordering)
         throws Exception
  {
    assertEquals(
         Filter.simplifyFilter(Filter.create(original), false).toString(),
         simplifiedWithoutReordering);
    assertEquals(
         Filter.simplifyFilter(Filter.create(original), true).toString(),
         simplifiedWithReordering);
  }



  /**
   * Retrieves test data for use with the simplifyFilter method.
   *
   * @return  Test data for use with the simplifyFilter method.
   */
  @DataProvider(name="simplifyFilterTestData")
  public Object[][] getSimplifyFilterTestData()
  {
    return new Object[][]
    {
      // Presence, not objectClass
      new String[]
      {
        "(uid=*)",
        "(uid=*)",
        "(uid=*)"
      },

      // Presence, with objectClass
      new String[]
      {
        "(objectClass=*)",
        "(objectClass=*)",
        "(objectClass=*)"
      },

      // Simple equality, not objectClass.
      new String[]
      {
        "(uid=john.doe)",
        "(uid=john.doe)",
        "(uid=john.doe)"
      },

      // Simple equality, with objectClass.
      new String[]
      {
        "(objectClass=person)",
        "(objectClass=person)",
        "(objectClass=person)"
      },

      // Substring with subInitial.
      new String[]
      {
        "(uid=john*)",
        "(uid=john*)",
        "(uid=john*)"
      },

      // Substring with subAny.
      new String[]
      {
        "(uid=*john*)",
        "(uid=*john*)",
        "(uid=*john*)"
      },

      // Substring with subFinal.
      new String[]
      {
        "(uid=*doe)",
        "(uid=*doe)",
        "(uid=*doe)"
      },

      // Substring with all components.
      new String[]
      {
        "(uid=john*.*doe)",
        "(uid=john*.*doe)",
        "(uid=john*.*doe)"
      },

      // Greater-or-equal.
      new String[]
      {
        "(integerValue>=5)",
        "(integerValue>=5)",
        "(integerValue>=5)"
      },

      // Less-or-equal.
      new String[]
      {
        "(integerValue<=5)",
        "(integerValue<=5)",
        "(integerValue<=5)"
      },

      // Approximate match.
      new String[]
      {
        "(givenName~=John)",
        "(givenName~=John)",
        "(givenName~=John)"
      },

      // Extensible match.
      new String[]
      {
        "(givenName:=John)",
        "(givenName:=John)",
        "(givenName:=John)"
      },

      // AND with zero components (LDAP true filter).
      new String[]
      {
        "(&)",
        "(&)",
        "(&)"
      },

      // OR with zero components (LDAP false filter).
      new String[]
      {
        "(|)",
        "(|)",
        "(|)"
      },

      // AND with one component.
      new String[]
      {
        "(&(uid=john.doe))",
        "(uid=john.doe)",
        "(uid=john.doe)"
      },

      // OR with one component.
      new String[]
      {
        "(|(uid=john.doe))",
        "(uid=john.doe)",
        "(uid=john.doe)"
      },

      // AND with two components that could potentially be reordered.
      new String[]
      {
        "(&(objectClass=person)(uid=john.doe))",
        "(&(objectClass=person)(uid=john.doe))",
        "(&(uid=john.doe)(objectClass=person))"
      },

      // OR with two components that could potentially be reordered.
      new String[]
      {
        "(|(objectClass=person)(uid=john.doe))",
        "(|(objectClass=person)(uid=john.doe))",
        "(|(uid=john.doe)(objectClass=person))"
      },

      // AND with a nested LDAP true filter.
      new String[]
      {
        "(&(&))",
        "(&)",
        "(&)"
      },

      // OR with a nested LDAP false filter.
      new String[]
      {
        "(|(|))",
        "(|)",
        "(|)"
      },

      // AND with a nested LDAP false filter.
      new String[]
      {
        "(&(|))",
        "(|)",
        "(|)"
      },

      // OR with a nested LDAP true filter.
      new String[]
      {
        "(|(&))",
        "(&)",
        "(&)"
      },

      // AND with a deeply-nested LDAP true filter.
      new String[]
      {
        "(&(&(&(&(&(&))))))",
        "(&)",
        "(&)"
      },

      // OR with a deeply-nested LDAP false filter.
      new String[]
      {
        "(|(|(|(|(|(|))))))",
        "(|)",
        "(|)"
      },

      // AND with a deeply-nested simple filter.
      new String[]
      {
        "(&(&(&(&(&(uid=john.doe))))))",
        "(uid=john.doe)",
        "(uid=john.doe)"
      },

      // OR with a deeply-nested simple filter.
      new String[]
      {
        "(|(|(|(|(|(uid=john.doe))))))",
        "(uid=john.doe)",
        "(uid=john.doe)"
      },

      // AND with duplicate elements in the same component.
      new String[]
      {
        "(&(a=b)(c=d)(a=b))",
        "(&(a=b)(c=d))",
        "(&(a=b)(c=d))"
      },

      // OR with duplicate elements in the same component.
      new String[]
      {
        "(|(a=b)(c=d)(a=b))",
        "(|(a=b)(c=d))",
        "(|(a=b)(c=d))"
      },

      // AND with duplicate elements in subordinate components.
      new String[]
      {
        "(&(&(a=b)(c=d))(&(a=b)(e=f)))",
        "(&(a=b)(c=d)(e=f))",
        "(&(a=b)(c=d)(e=f))"
      },

      // OR with duplicate elements in subordinate components.
      new String[]
      {
        "(|(|(a=b)(c=d))(|(a=b)(e=f)))",
        "(|(a=b)(c=d)(e=f))",
        "(|(a=b)(c=d)(e=f))"
      },

      // NOT with a simple embedded component.
      new String[]
      {
        "(!(a=b))",
        "(!(a=b))",
        "(!(a=b))"
      },

      // NOT with an embedded AND component that only has one element.
      new String[]
      {
        "(!(&(a=b)))",
        "(!(a=b))",
        "(!(a=b))"
      },

      // NOT with an embedded AND component that has multiple elements.
      new String[]
      {
        "(!(&(a=b)(c=d)(&(e=f)(a=b))))",
        "(!(&(a=b)(c=d)(e=f)))",
        "(!(&(a=b)(c=d)(e=f)))"
      },

      // A big filter that encapsulates a lot of cases.
      new String[]
      {
        "(&(eq1=1)(objectClass=ocEq1)(pr1=*)(objectClass=*)(si1=1*)(sa1=*1*)" +
             "(sf1=*1)(ge1>=1)(le1<=1)(am1~=1)(em1:=1)(&(eq2=2)" +
             "(objectClass=ocEq1)(objectClass=ocEq2)(pr2=*)(ss2=2*2*2))" +
             "(!(eq3=3))(!(&(eq4=4)(eq4=4)))(!(|(objectClass=ocEq3)(eq5=5)))" +
             "(|(&)(eq2=2)(objectClass=ocEq1)(objectClass=ocEq2)(pr1=*)" +
             "(pr2=*)(objectClass=*)(ss2=2*2*2)))",
        "(&(eq1=1)(objectClass=ocEq1)(pr1=*)(objectClass=*)(si1=1*)(sa1=*1*)" +
             "(sf1=*1)(ge1>=1)(le1<=1)(am1~=1)(em1:=1)(eq2=2)" +
             "(objectClass=ocEq2)(pr2=*)(ss2=2*2*2)(!(eq3=3))(!(eq4=4))" +
             "(!(|(objectClass=ocEq3)(eq5=5))))",
        "(&(eq1=1)(eq2=2)(objectClass=ocEq1)(objectClass=ocEq2)(am1~=1)" +
             "(pr1=*)(pr2=*)(si1=1*)(ss2=2*2*2)(sa1=*1*)(sf1=*1)(ge1>=1)" +
             "(le1<=1)(em1:=1)(objectClass=*)(!(eq3=3))(!(eq4=4))" +
             "(!(|(eq5=5)(objectClass=ocEq3))))"
      },

      // AND that contains an LDAP false filter in the top level.
      new String[]
      {
        "(&(objectClass=*)(|))",
        "(|)",
        "(|)"
      },

      // AND that contains an LDAP false filter in a nested level.
      new String[]
      {
        "(&(objectClass=*)(&(objectClass=top)(|)))",
        "(|)",
        "(|)"
      },

      // OR that contains an LDAP true filter in the top level.
      new String[]
      {
        "(|(objectClass=*)(&))",
        "(&)",
        "(&)"
      },

      // OR that contains an LDAP true filter in a nested level.
      new String[]
      {
        "(|(objectClass=*)(|(objectClass=top)(&)))",
        "(&)",
        "(&)"
      },
    };
  }
}
