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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.toUTF8String;



/**
 * This class provides a set of test cases for the MatchedValuesFilter class.
 */
public class MatchedValuesFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code createEqualityFilter} method with valid string arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterStringValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createEqualityFilter("foo", "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA3);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=bar)");
  }



  /**
   * Tests the {@code createEqualityFilter} method with a {@code null} attribute
   * type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createEqualityFilter(null, "bar");
  }



  /**
   * Tests the {@code createEqualityFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterStringNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createEqualityFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createEqualityFilter} method with valid byte[] arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateEqualityFilterBytesValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createEqualityFilter("foo",
                                                  "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA3);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=bar)");
  }



  /**
   * Tests the {@code createEqualityFilter} method with a {@code null} attribute
   * type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterBytesNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createEqualityFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createEqualityFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateEqualityFilterBytesNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createEqualityFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid string arguments.
   * It will contain only the subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringValidSubInitial()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", "bar", null, null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNotNull(f.getSubInitialValue());
    assertEquals(f.getSubInitialValue(), "bar");

    assertNotNull(f.getSubInitialValueBytes());
    assertEquals(toUTF8String(f.getSubInitialValueBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=bar*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid string arguments.
   * It will contain only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringValidSingleSubAny()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null,
                                                   new String[] { "bar" },
                                                   null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 1);
    assertEquals(f.getSubAnyValues()[0], "bar");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 1);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "bar");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "bar");

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*bar*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid string arguments.
   * It will contain only a set of subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringValidMultipleSubAny()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null,
                                                   new String[] { "a", "b" },
                                                   null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 2);
    assertEquals(f.getSubAnyValues()[0], "a");
    assertEquals(f.getSubAnyValues()[1], "b");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 2);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "a");
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[1]), "b");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 2);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "a");
    assertEquals(f.getRawSubAnyValues()[1].stringValue(), "b");

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*a*b*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid string arguments.
   * It will contain only the subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringValidSubFinal()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null, null, "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNotNull(f.getSubFinalValue());
    assertEquals(f.getSubFinalValue(), "bar");

    assertNotNull(f.getSubFinalValueBytes());
    assertEquals(toUTF8String(f.getSubFinalValueBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*bar)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid string arguments.
   * It will contain all substring elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterStringValidAllElements()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", "a",
                                                   new String[] { "b", "c" },
                                                   "d");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNotNull(f.getSubInitialValue());
    assertEquals(f.getSubInitialValue(), "a");

    assertNotNull(f.getSubInitialValueBytes());
    assertEquals(toUTF8String(f.getSubInitialValueBytes()), "a");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "a");

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 2);
    assertEquals(f.getSubAnyValues()[0], "b");
    assertEquals(f.getSubAnyValues()[1], "c");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 2);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "b");
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[1]), "c");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 2);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "b");
    assertEquals(f.getRawSubAnyValues()[1].stringValue(), "c");

    assertNotNull(f.getSubFinalValue());
    assertEquals(f.getSubFinalValue(), "d");

    assertNotNull(f.getSubFinalValueBytes());
    assertEquals(toUTF8String(f.getSubFinalValueBytes()), "d");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "d");

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=a*b*c*d)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with a {@code null}
   * attribute type with string substring types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter(null, "a", null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with all {@code null}
   * string substring elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullSubstringElements()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter("foo", (String) null, null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with {@code null} string
   * subInitial and subFinal elements and an empty subAny array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterStringNullOrEmptySubstringElements()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter("foo", null, new String[0], null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid byte[] arguments.
   * It will contain only the subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterBytesValidSubInitial()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo",
                                                   "bar".getBytes("UTF-8"),
                                                   null, null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNotNull(f.getSubInitialValue());
    assertEquals(f.getSubInitialValue(), "bar");

    assertNotNull(f.getSubInitialValueBytes());
    assertEquals(toUTF8String(f.getSubInitialValueBytes()), "bar");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "bar");

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=bar*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid byte[] arguments.
   * It will contain only a single subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterBytesValidSingleSubAny()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null,
              new byte[][] { "bar".getBytes("UTF-8") }, null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 1);
    assertEquals(f.getSubAnyValues()[0], "bar");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 1);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "bar");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 1);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "bar");

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*bar*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid byte[] arguments.
   * It will contain only a set of subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterBytesValidMultipleSubAny()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null,
              new byte[][] { "a".getBytes("UTF-8"), "b".getBytes("UTF-8") },
              null);
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 2);
    assertEquals(f.getSubAnyValues()[0], "a");
    assertEquals(f.getSubAnyValues()[1], "b");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 2);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "a");
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[1]), "b");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 2);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "a");
    assertEquals(f.getRawSubAnyValues()[1].stringValue(), "b");

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*a*b*)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid byte[] arguments.
   * It will contain only the subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterBytesValidSubFinal()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", null, null,
                                                   "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNotNull(f.getSubFinalValue());
    assertEquals(f.getSubFinalValue(), "bar");

    assertNotNull(f.getSubFinalValueBytes());
    assertEquals(toUTF8String(f.getSubFinalValueBytes()), "bar");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "bar");

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*bar)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with valid byte[] arguments.
   * It will contain all substring elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSubstringFilterBytesValidAllElements()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createSubstringFilter("foo", "a".getBytes("UTF-8"),
              new byte[][] { "b".getBytes("UTF-8"), "c".getBytes("UTF-8") },
              "d".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA4);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNotNull(f.getSubInitialValue());
    assertEquals(f.getSubInitialValue(), "a");

    assertNotNull(f.getSubInitialValueBytes());
    assertEquals(toUTF8String(f.getSubInitialValueBytes()), "a");

    assertNotNull(f.getRawSubInitialValue());
    assertEquals(f.getRawSubInitialValue().stringValue(), "a");

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 2);
    assertEquals(f.getSubAnyValues()[0], "b");
    assertEquals(f.getSubAnyValues()[1], "c");

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 2);
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[0]), "b");
    assertEquals(toUTF8String(f.getSubAnyValueBytes()[1]), "c");

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 2);
    assertEquals(f.getRawSubAnyValues()[0].stringValue(), "b");
    assertEquals(f.getRawSubAnyValues()[1].stringValue(), "c");

    assertNotNull(f.getSubFinalValue());
    assertEquals(f.getSubFinalValue(), "d");

    assertNotNull(f.getSubFinalValueBytes());
    assertEquals(toUTF8String(f.getSubFinalValueBytes()), "d");

    assertNotNull(f.getRawSubFinalValue());
    assertEquals(f.getRawSubFinalValue().stringValue(), "d");

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=a*b*c*d)");
  }



  /**
   * Tests the {@code createSubstringFilter} method with a {@code null}
   * attribute type with byte[] substring types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterBytesNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter(null, "a".getBytes("UTF-8"), null,
                                              null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with all {@code null}
   * byte[] substring elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterBytesNullSubstringElements()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter("foo", (byte[]) null, null, null);
  }



  /**
   * Tests the {@code createSubstringFilter} method with {@code null} byte[]
   * subInitial and subFinal elements and an empty subAny array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateSubstringFilterBytesNullOrEmptySubstringElements()
         throws Exception
  {
    MatchedValuesFilter.createSubstringFilter("foo", null, new byte[0][], null);
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with valid string
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterStringValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createGreaterOrEqualFilter("foo", "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA5);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo>=bar)");
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createGreaterOrEqualFilter(null, "bar");
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterStringNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createGreaterOrEqualFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with valid byte[]
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGreaterOrEqualFilterBytesValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createGreaterOrEqualFilter("foo",
              "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA5);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo>=bar)");
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterBytesNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createGreaterOrEqualFilter(null,
                                                   "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createGreaterOrEqualFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateGreaterOrEqualFilterBytesNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createGreaterOrEqualFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with valid string
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterStringValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createLessOrEqualFilter("foo", "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA6);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo<=bar)");
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createLessOrEqualFilter(null, "bar");
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterStringNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createLessOrEqualFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with valid byte[]
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLessOrEqualFilterBytesValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createLessOrEqualFilter("foo",
              "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA6);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo<=bar)");
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterBytesNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createLessOrEqualFilter(null, "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createLessOrEqualFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLessOrEqualFilterBytesNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createLessOrEqualFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createPresentFilter} method with valid string arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePresentFilterStringValid()
         throws Exception
  {
    MatchedValuesFilter f = MatchedValuesFilter.createPresentFilter("foo");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0x87);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNull(f.getAssertionValue());
    assertNull(f.getAssertionValueBytes());
    assertNull(f.getRawAssertionValue());

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo=*)");
  }



  /**
   * Tests the {@code createPresentFilter} method with a {@code null} attribute
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreatePresentFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createPresentFilter(null);
  }



  /**
   * Tests the {@code createApproximateFilter} method with valid string
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateFilterStringValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createApproximateFilter("foo", "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA8);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo~=bar)");
  }



  /**
   * Tests the {@code createApproximateFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateFilterStringNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createApproximateFilter(null, "bar");
  }



  /**
   * Tests the {@code createApproximateFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateFilterStringNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createApproximateFilter("foo", (String) null);
  }



  /**
   * Tests the {@code createApproximateFilter} method with valid byte[]
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateApproximateFilterBytesValid()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createApproximateFilter("foo",
                                                     "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA8);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo~=bar)");
  }



  /**
   * Tests the {@code createApproximateFilter} method with a {@code null}
   * attribute type and non-{@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateFilterBytesNullAttributeType()
         throws Exception
  {
    MatchedValuesFilter.createApproximateFilter(null,
                                                "bar".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createApproximateFilter} method with a non-{@code null}
   * attribute type and {@code null} assertion value string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateApproximateFilterBytesNullAssertionValue()
         throws Exception
  {
    MatchedValuesFilter.createApproximateFilter("foo", (byte[]) null);
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with an attribute
   * type and string value but no matching rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringNoMRID()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter("foo", null, "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo:=bar)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a matching rule
   * ID and string value but no attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringNoAT()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter(null, "foo", "bar");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNull(f.getAttributeType());

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertEquals(f.toString(), "(:foo:=bar)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with an attribute
   * type, matching rule ID, and string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterStringAll()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter("foo", "bar", "baz");
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertEquals(f.toString(), "(foo:bar:=baz)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a string value
   * but neither an attribute type nor a matching rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterStringNoATOrMRID()
         throws Exception
  {
    MatchedValuesFilter.createExtensibleMatchFilter(null, null, "foo");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a null string
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterStringNoValue()
         throws Exception
  {
    MatchedValuesFilter.createExtensibleMatchFilter("foo", null, (String) null);
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with an attribute
   * type and byte[] value but no matching rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterBytesNoMRID()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter("foo", null,
              "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNull(f.getMatchingRuleID());

    assertEquals(f.toString(), "(foo:=bar)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a matching rule
   * ID and byte[] value but no attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterBytesNoAT()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter(null, "foo",
              "bar".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNull(f.getAttributeType());

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "bar");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "bar");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "bar");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "foo");

    assertEquals(f.toString(), "(:foo:=bar)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with an attribute
   * type, matching rule ID, and byte[] value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateExtensibleMatchFilterBytesAll()
         throws Exception
  {
    MatchedValuesFilter f =
         MatchedValuesFilter.createExtensibleMatchFilter("foo", "bar",
              "baz".getBytes("UTF-8"));
    f = MatchedValuesFilter.decode(f.encode());
    f = MatchedValuesFilter.create(f.toFilter());

    assertEquals(f.getMatchType(), (byte) 0xA9);

    assertNotNull(f.getAttributeType());
    assertEquals(f.getAttributeType(), "foo");

    assertNotNull(f.getAssertionValue());
    assertEquals(f.getAssertionValue(), "baz");

    assertNotNull(f.getAssertionValueBytes());
    assertEquals(toUTF8String(f.getAssertionValueBytes()), "baz");

    assertNotNull(f.getRawAssertionValue());
    assertEquals(f.getRawAssertionValue().stringValue(), "baz");

    assertNull(f.getSubInitialValue());
    assertNull(f.getSubInitialValueBytes());
    assertNull(f.getRawSubInitialValue());

    assertNotNull(f.getSubAnyValues());
    assertEquals(f.getSubAnyValues().length, 0);

    assertNotNull(f.getSubAnyValueBytes());
    assertEquals(f.getSubAnyValueBytes().length, 0);

    assertNotNull(f.getRawSubAnyValues());
    assertEquals(f.getRawSubAnyValues().length, 0);

    assertNull(f.getSubFinalValue());
    assertNull(f.getSubFinalValueBytes());
    assertNull(f.getRawSubFinalValue());

    assertNotNull(f.getMatchingRuleID());
    assertEquals(f.getMatchingRuleID(), "bar");

    assertEquals(f.toString(), "(foo:bar:=baz)");
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a byte[] value
   * but neither an attribute type nor a matching rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterBytesNoATOrMRID()
         throws Exception
  {
    MatchedValuesFilter.createExtensibleMatchFilter(null, null,
                                                    "foo".getBytes("UTF-8"));
  }



  /**
   * Tests the {@code createExtensibleMatchFilter} method with a null byte[]
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateExtensibleMatchFilterBytesNoValue()
         throws Exception
  {
    MatchedValuesFilter.createExtensibleMatchFilter("foo", null, (byte[]) null);
  }



  /**
   * Tests the {@code create} method with an AND filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateANDFilter()
         throws Exception
  {
    MatchedValuesFilter.create(Filter.create("(&(a=b)(c=d))"));
  }



  /**
   * Tests the {@code create} method with an OR filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateORFilter()
         throws Exception
  {
    MatchedValuesFilter.create(Filter.create("(|(a=b)(c=d))"));
  }



  /**
   * Tests the {@code create} method with a NOT filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateNOTFilter()
         throws Exception
  {
    MatchedValuesFilter.create(Filter.create("(!(a=b))"));
  }



  /**
   * Tests the {@code create} method with an extensible matching filter with the
   * dnAttributes flag set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateExtensibleMatchFilterWithDNAttributes()
         throws Exception
  {
    MatchedValuesFilter.create(Filter.create("(a:dn:=b)"));
  }



  /**
   * Tests the {@code decode} method with an element with an invalid type.
   *
   * @throws  Exception  If an invalid problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidType()
         throws Exception
  {
    MatchedValuesFilter.decode(new ASN1Element((byte) 0x00));
  }



  /**
   * Tests the {@code decode} method with a malformed attribute-value assertion.
   *
   * @throws  Exception  If an invalid problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidAVA()
         throws Exception
  {
    MatchedValuesFilter.decode(new ASN1Sequence((byte) 0xA3));
  }



  /**
   * Tests the {@code decode} method with a malformed substring filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSubstringMalformed()
         throws Exception
  {
    MatchedValuesFilter.decode(
         new ASN1Element((byte) 0xA4, new byte[] { 0x01 }));
  }



  /**
   * Tests the {@code decode} method with a substring filter containing no
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSubstringNoElements()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence((byte) 0xA4,
         new ASN1OctetString("foo"),
         new ASN1Sequence());
    MatchedValuesFilter.decode(s);
  }



  /**
   * Tests the {@code decode} method with a substring element with multiple
   * subInitial values.
   *
   * @throws  Exception  If an invalid problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMultipleSubInitial()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence((byte) 0xA4,
         new ASN1OctetString("foo"),
         new ASN1Sequence(
                  new ASN1OctetString((byte) 0x80, "bar"),
                  new ASN1OctetString((byte) 0x80, "baz")));
    MatchedValuesFilter.decode(s);
  }



  /**
   * Tests the {@code decode} method with a substring element with multiple
   * subFinal values.
   *
   * @throws  Exception  If an invalid problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMultipleSubFinal()
         throws Exception
  {
    ASN1Sequence s = new ASN1Sequence((byte) 0xA4,
         new ASN1OctetString("foo"),
         new ASN1Sequence(
                  new ASN1OctetString((byte) 0x82, "bar"),
                  new ASN1OctetString((byte) 0x82, "baz")));
    MatchedValuesFilter.decode(s);
  }
}
